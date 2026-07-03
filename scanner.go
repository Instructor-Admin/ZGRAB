package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// =============================================================================
// КОНФИГУРАЦИЯ
// =============================================================================

type Config struct {
	SrcDB            string
	DstDB            string
	ChunkSize        int
	Concurrency      int
	Timeout          time.Duration
	BatchSize        int
	SpeedLogInterval time.Duration
}

func LoadConfig() Config {
	return Config{
		SrcDB:            envOrDefault("SRC_DB_URL", "postgres://admin:admin@45.150.34.172:5432/mydb?sslmode=disable"),
		DstDB:            envOrDefault("DST_DB_URL", "postgres://admin:admin@45.150.34.172:5432/mydb?sslmode=disable"),
		ChunkSize:        envIntOrDefault("CHUNK_SIZE", 5000),
		Concurrency:      envIntOrDefault("CONCURRENCY", 2000),
		Timeout:          time.Duration(envIntOrDefault("TIMEOUT", 8)) * time.Second,
		BatchSize:        envIntOrDefault("BATCH_SIZE", 500),
		SpeedLogInterval: time.Duration(envIntOrDefault("SPEED_LOG_INTERVAL", 10)) * time.Second,
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

// =============================================================================
// СИГНАТУРЫ
// =============================================================================

var fortiCertMarkers = []string{
	"support@fortinet.com",
	"ou = fortigate", "ou = fortiweb", "ou = fortiproxy", "ou = fortimail",
	"cn = fortigate", "cn = fortiweb", "cn = fortiproxy", "cn = fortimail",
	"cn = fgt_", "o = fortinet",
	"899 kifer road", "sunnyvale",
}

var tableRe = regexp.MustCompile(`^([a-z]{2,3})_(\d{1,5})$`)

func detectVendor(output string) string {
	if len(output) < 10 {
		return ""
	}
	lower := strings.ToLower(output)

	for _, marker := range fortiCertMarkers {
		if strings.Contains(lower, marker) {
			return "fortinet"
		}
	}

	if matched, _ := regexp.MatchString(
		`server:\s*(fortigate|fortiweb|fortiproxy|fortimail|fortinet|fortisandbox)`, lower,
	); matched {
		return "fortinet"
	}

	fortiBody := []string{"fgt_lang", "apscoo", "fortiwaf", "/remote/login", "sslvpn_portal", "fortitoken"}
	for _, m := range fortiBody {
		if strings.Contains(lower, m) {
			return "fortinet"
		}
	}

	if strings.Contains(lower, "/+cscoe+/") {
		return "cisco"
	}

	if matched, _ := regexp.MatchString(
		`server:\s*(cisco-asa|cisco-sslvpn|webvpn|anyconnect)`, lower,
	); matched {
		return "cisco"
	}

	ciscoCookies := []string{"webvpn", "anyconnect", "csco_"}
	for _, c := range ciscoCookies {
		if strings.Contains(lower, c) {
			return "cisco"
		}
	}

	return ""
}

// =============================================================================
// СТРУКТУРЫ ДАННЫХ
// =============================================================================

type ScanRecord struct {
	SourceID int64
	Target   sql.NullString
	IP       string
	Port     int
}

type ScanResult struct {
	SourceID int64
	Target   string
	IP       string
	Port     int
	Vendor   string
	Data     string
}

// =============================================================================
// ОЧИСТКА UTF-8
// =============================================================================

func cleanUTF8(s string) string {
	var builder strings.Builder
	builder.Grow(len(s))

	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' ||
			(r >= 0x20 && r <= 0x7E) ||
			(r >= 0xA0 && r <= 0x10FFFF) {
			builder.WriteRune(r)
		} else if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			builder.WriteByte(' ')
		}
	}
	return builder.String()
}

// =============================================================================
// RAW TLS SCANNER
// =============================================================================

type TLSScanner struct {
	dialTimeout  time.Duration
	readTimeout  time.Duration
	tlsConfig    *tls.Config
	totalScanned atomic.Int64
	vendorStats  sync.Map
	startTime    time.Time
	lastLogTime  atomic.Value
	logInterval  time.Duration
}

func NewTLSScanner(concurrency int, timeout time.Duration, logInterval time.Duration) *TLSScanner {
	lt := time.Time{}
	lastLogAtomic := atomic.Value{}
	lastLogAtomic.Store(lt)

	return &TLSScanner{
		dialTimeout: 1 * time.Second,
		readTimeout: 2 * time.Second,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
		startTime:   time.Now(),
		lastLogTime: lastLogAtomic,
		logInterval: logInterval,
	}
}

func (s *TLSScanner) rawScan(ctx context.Context, record ScanRecord) *ScanResult {
	s.totalScanned.Add(1)
	addr := net.JoinHostPort(record.IP, strconv.Itoa(record.Port))

	// TCP SYN: 1 секунда
	dialer := net.Dialer{Timeout: s.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// TLS + HTTP: 2 секунды
	conn.SetDeadline(time.Now().Add(s.readTimeout))

	tlsCfg := s.tlsConfig.Clone()
	tlsCfg.ServerName = record.IP

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return s.httpFallback(conn, record)
	}
	defer tlsConn.Close()

	certInfo := s.extractCertInfo(tlsConn)

	httpReq := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		record.IP,
	)
	if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
		return nil
	}

	var response strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
			if response.Len() > 16384 {
				break
			}
		}
		if err != nil {
			break
		}
	}

	output := certInfo + response.String()
	vendor := detectVendor(output)
	if vendor == "" {
		return nil
	}

	data := cleanUTF8(output)
	if len(data) > 10000 {
		data = data[:10000]
	}

	s.incrementVendor(vendor)
	s.maybeLogSpeed()

	target := ""
	if record.Target.Valid {
		target = record.Target.String
	}

	return &ScanResult{
		SourceID: record.SourceID,
		Target:   target,
		IP:       record.IP,
		Port:     record.Port,
		Vendor:   vendor,
		Data:     data,
	}
}

func (s *TLSScanner) extractCertInfo(tlsConn *tls.Conn) string {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}

	cert := state.PeerCertificates[0]
	var info strings.Builder
	info.WriteString(fmt.Sprintf("Subject: %s\n", cert.Subject.String()))
	info.WriteString(fmt.Sprintf("Issuer: %s\n", cert.Issuer.String()))
	if len(cert.DNSNames) > 0 {
		info.WriteString(fmt.Sprintf("DNS: %s\n", strings.Join(cert.DNSNames, " ")))
	}
	info.WriteString("---\n")
	return info.String()
}

func (s *TLSScanner) httpFallback(conn net.Conn, record ScanRecord) *ScanResult {
	conn.SetDeadline(time.Now().Add(s.readTimeout))

	httpReq := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		record.IP, record.Port,
	)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return nil
	}

	var response strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
			if response.Len() > 16384 {
				break
			}
		}
		if err != nil {
			break
		}
	}

	output := response.String()
	vendor := detectVendor(output)
	if vendor == "" {
		return nil
	}

	data := cleanUTF8(output)
	if len(data) > 10000 {
		data = data[:10000]
	}

	s.incrementVendor(vendor)
	s.maybeLogSpeed()

	target := ""
	if record.Target.Valid {
		target = record.Target.String
	}

	return &ScanResult{
		SourceID: record.SourceID,
		Target:   target,
		IP:       record.IP,
		Port:     record.Port,
		Vendor:   vendor,
		Data:     data,
	}
}

func (s *TLSScanner) incrementVendor(vendor string) {
	val, _ := s.vendorStats.LoadOrStore(vendor, new(atomic.Int64))
	val.(*atomic.Int64).Add(1)
}

func (s *TLSScanner) maybeLogSpeed() {
	now := time.Now()
	lastLog := s.lastLogTime.Load().(time.Time)

	if now.Sub(lastLog) >= s.logInterval {
		s.lastLogTime.Store(now)

		elapsed := now.Sub(s.startTime).Seconds()
		total := s.totalScanned.Load()
		rate := float64(total) / elapsed

		stats := make(map[string]int64)
		s.vendorStats.Range(func(key, value interface{}) bool {
			stats[key.(string)] = value.(*atomic.Int64).Load()
			return true
		})

		log.Printf("⚡ %.0f IP/s | всего: %d | найдено: %d | %v",
			rate, total, sumMapValues(stats), topVendors(stats, 3))
	}
}

func (s *TLSScanner) GetStats() map[string]interface{} {
	elapsed := time.Since(s.startTime).Seconds()
	total := s.totalScanned.Load()

	stats := make(map[string]int64)
	s.vendorStats.Range(func(key, value interface{}) bool {
		stats[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})

	return map[string]interface{}{
		"total_scanned": total,
		"total_found":   sumMapValues(stats),
		"vendors":       stats,
		"elapsed":       elapsed,
		"rate":          float64(total) / elapsed,
	}
}

func sumMapValues(m map[string]int64) int64 {
	var sum int64
	for _, v := range m {
		sum += v
	}
	return sum
}

func topVendors(m map[string]int64, n int) string {
	type kv struct {
		k string
		v int64
	}
	var items []kv
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].v > items[i].v {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	if len(items) > n {
		items = items[:n]
	}
	var parts []string
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s:%d", item.k, item.v))
	}
	return strings.Join(parts, " ")
}

// =============================================================================
// WORKER POOL
// =============================================================================

type WorkerPool struct {
	scanner *TLSScanner
	tasks   chan ScanRecord
	results chan *ScanResult
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewWorkerPool(ctx context.Context, scanner *TLSScanner, concurrency int) *WorkerPool {
	ctx, cancel := context.WithCancel(ctx)

	wp := &WorkerPool{
		scanner: scanner,
		tasks:   make(chan ScanRecord, concurrency*2),
		results: make(chan *ScanResult, concurrency*2),
		ctx:     ctx,
		cancel:  cancel,
	}

	for i := 0; i < concurrency; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}

	go func() {
		wp.wg.Wait()
		close(wp.results)
	}()

	return wp
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case record, ok := <-wp.tasks:
			if !ok {
				return
			}
			result := wp.scanner.rawScan(wp.ctx, record)
			if result != nil {
				select {
				case wp.results <- result:
				case <-wp.ctx.Done():
					return
				}
			}
		}
	}
}

func (wp *WorkerPool) Submit(record ScanRecord) {
	select {
	case wp.tasks <- record:
	case <-wp.ctx.Done():
	}
}

func (wp *WorkerPool) Close() {
	close(wp.tasks)
}

func (wp *WorkerPool) Results() <-chan *ScanResult {
	return wp.results
}

// =============================================================================
// БАЗА ДАННЫХ
// =============================================================================

type DB struct {
	src *pgxpool.Pool
	dst *pgxpool.Pool
}

func NewDB(cfg Config) (*DB, error) {
	srcConfig, err := pgxpool.ParseConfig(cfg.SrcDB)
	if err != nil {
		return nil, fmt.Errorf("src db config: %w", err)
	}
	srcConfig.MinConns = 5
	srcConfig.MaxConns = 20

	src, err := pgxpool.NewWithConfig(context.Background(), srcConfig)
	if err != nil {
		return nil, fmt.Errorf("src db connect: %w", err)
	}

	dstConfig, err := pgxpool.ParseConfig(cfg.DstDB)
	if err != nil {
		src.Close()
		return nil, fmt.Errorf("dst db config: %w", err)
	}
	dstConfig.MinConns = 10
	dstConfig.MaxConns = 30

	dst, err := pgxpool.NewWithConfig(context.Background(), dstConfig)
	if err != nil {
		src.Close()
		return nil, fmt.Errorf("dst db connect: %w", err)
	}

	return &DB{src: src, dst: dst}, nil
}

func (db *DB) Setup(ctx context.Context) error {
	_, err := db.dst.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS zgrab_scan_progress (
			source_table TEXT NOT NULL,
			scan_name TEXT NOT NULL DEFAULT 'ssl',
			last_id BIGINT DEFAULT 0,
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			PRIMARY KEY (source_table, scan_name)
		);
	`)
	return err
}

func (db *DB) GetTables(ctx context.Context) ([]string, error) {
	rows, err := db.src.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema='public' ORDER BY table_name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if tableRe.MatchString(name) || strings.HasPrefix(name, "all_") {
			tables = append(tables, name)
		}
	}
	return tables, nil
}

func (db *DB) GetTotal(ctx context.Context, table string) (int64, error) {
	var count int64
	err := db.src.QueryRow(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, table),
	).Scan(&count)
	return count, err
}

func (db *DB) EnsureResult(ctx context.Context, table string) error {
	_, err := db.dst.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id BIGSERIAL PRIMARY KEY,
			source_id BIGINT,
			target TEXT,
			ip_addr INET NOT NULL,
			port INTEGER NOT NULL,
			country TEXT,
			scan_name TEXT DEFAULT 'ssl',
			matched_vendor TEXT,
			data TEXT,
			scanned_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE (ip_addr, port)
		);
	`, table))
	return err
}

func (db *DB) GetProgress(ctx context.Context, table string) (int64, error) {
	var lastID sql.NullInt64
	err := db.dst.QueryRow(ctx,
		"SELECT last_id FROM zgrab_scan_progress WHERE source_table = $1", table,
	).Scan(&lastID)
	if err != nil || !lastID.Valid {
		return 0, nil
	}
	return lastID.Int64, nil
}

func (db *DB) UpdateProgress(ctx context.Context, table string, lastID int64) error {
	_, err := db.dst.Exec(ctx, `
		INSERT INTO zgrab_scan_progress (source_table, scan_name, last_id, updated_at)
		VALUES ($1, 'ssl', $2, NOW())
		ON CONFLICT (source_table, scan_name)
		DO UPDATE SET last_id = $2, updated_at = NOW();
	`, table, lastID)
	return err
}

func (db *DB) FetchChunk(ctx context.Context, table string, lastID int64, limit int) ([]ScanRecord, error) {
	ipCol, err := db.getIPColumn(ctx, table)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(
		`SELECT id, target, "%s"::TEXT, port FROM "%s" WHERE id > $1 ORDER BY id LIMIT $2`,
		ipCol, table,
	)

	rows, err := db.src.Query(ctx, query, lastID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		var ipText string
		if err := rows.Scan(&r.SourceID, &r.Target, &ipText, &r.Port); err != nil {
			return nil, err
		}
		r.IP = strings.Split(ipText, "/")[0]
		records = append(records, r)
	}
	return records, nil
}

func (db *DB) getIPColumn(ctx context.Context, table string) (string, error) {
	rows, err := db.src.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_name=$1 AND column_name IN ('ip_addr','ip')
	`, table)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var col string
	if rows.Next() {
		if err := rows.Scan(&col); err != nil {
			return "", err
		}
	}
	if col == "" {
		col = "ip_addr"
	}
	return col, nil
}

func (db *DB) InsertBatch(ctx context.Context, table string, results []*ScanResult, country string) (int, error) {
	if len(results) == 0 {
		return 0, nil
	}

	total := 0
	batchSize := 200

	for i := 0; i < len(results); i += batchSize {
		end := i + batchSize
		if end > len(results) {
			end = len(results)
		}
		batch := results[i:end]

		var placeholders []string
		var args []interface{}
		phIdx := 0

		for _, r := range batch {
			base := phIdx
			placeholders = append(placeholders, fmt.Sprintf(
				"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				base+1, base+2, base+3, base+4,
				base+5, base+6, base+7, base+8,
			))

			cleanData := strings.ReplaceAll(r.Data, "\x00", "")
			if len(cleanData) > 10000 {
				cleanData = cleanData[:10000]
			}

			args = append(args,
				r.SourceID,
				nullString(r.Target),
				r.IP,
				r.Port,
				country,
				"ssl",
				r.Vendor,
				cleanData,
			)
			phIdx += 8
		}

		query := fmt.Sprintf(`
			INSERT INTO %s
			(source_id, target, ip_addr, port, country, scan_name, matched_vendor, data)
			VALUES %s
			ON CONFLICT (ip_addr, port) DO UPDATE SET
				source_id = EXCLUDED.source_id,
				target = EXCLUDED.target,
				matched_vendor = EXCLUDED.matched_vendor,
				data = EXCLUDED.data,
				scanned_at = NOW()
		`, table, strings.Join(placeholders, ","))

		_, err := db.dst.Exec(ctx, query, args...)
		if err != nil {
			log.Printf("Batch insert error, falling back to single: %v", err)
			for _, r := range batch {
				singleQuery := fmt.Sprintf(`
					INSERT INTO %s
					(source_id, target, ip_addr, port, country, scan_name, matched_vendor, data)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
					ON CONFLICT (ip_addr, port) DO UPDATE SET
						source_id = EXCLUDED.source_id,
						target = EXCLUDED.target,
						matched_vendor = EXCLUDED.matched_vendor,
						data = EXCLUDED.data,
						scanned_at = NOW()
				`, table)

				cleanSingle := strings.ReplaceAll(r.Data, "\x00", "")
				if len(cleanSingle) > 10000 {
					cleanSingle = cleanSingle[:10000]
				}

				if _, err := db.dst.Exec(ctx, singleQuery,
					r.SourceID, nullString(r.Target), r.IP, r.Port,
					country, "ssl", r.Vendor, cleanSingle,
				); err != nil {
					log.Printf("Single insert failed for %s:%d — skipped", r.IP, r.Port)
					continue
				}
				total++
			}
			continue
		}
		total += len(batch)
	}

	return total, nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

func (db *DB) Close() {
	if db.src != nil {
		db.src.Close()
	}
	if db.dst != nil {
		db.dst.Close()
	}
}

// =============================================================================
// ОБРАБОТКА ТАБЛИЦЫ
// =============================================================================

func processTable(
	ctx context.Context,
	scanner *TLSScanner,
	db *DB,
	tableName string,
	chunkSize int,
	concurrency int,
) error {
	match := tableRe.FindStringSubmatch(tableName)
	if match == nil {
		return nil
	}

	country := match[1]
	port, _ := strconv.Atoi(match[2])
	resultTable := fmt.Sprintf("banners_tls_%s_%d", country, port)

	total, _ := db.GetTotal(ctx, tableName)

	log.Println("")
	log.Printf("ТАБЛИЦА: %s | Порт: %d → %s | Всего: %s",
		tableName, port, resultTable, formatInt(total))

	if err := db.EnsureResult(ctx, resultTable); err != nil {
		return fmt.Errorf("ensure result: %w", err)
	}

	lastID, _ := db.GetProgress(ctx, tableName)
	totalSaved := 0
	chunkNum := 0

	for {
		records, err := db.FetchChunk(ctx, tableName, lastID, chunkSize)
		if err != nil {
			return fmt.Errorf("fetch chunk: %w", err)
		}
		if len(records) == 0 {
			log.Printf("✔ %s завершена. Сохранено: %d", tableName, totalSaved)
			return nil
		}

		chunkNum++
		chunkLastID := records[len(records)-1].SourceID
		chunkStart := time.Now()

		log.Printf("ЧАНК #%d: %d → %d (%d записей)",
			chunkNum, records[0].SourceID, chunkLastID, len(records))

		wp := NewWorkerPool(ctx, scanner, concurrency)

		go func() {
			for _, r := range records {
				wp.Submit(r)
			}
			wp.Close()
		}()

		var results []*ScanResult
		for r := range wp.Results() {
			results = append(results, r)
		}

		if len(results) > 0 {
			inserted, _ := db.InsertBatch(ctx, resultTable, results, country)
			totalSaved += inserted

			vendorCounts := make(map[string]int)
			for _, r := range results {
				vendorCounts[r.Vendor]++
			}
			log.Printf("│ Сохранено: %d | %v", inserted, vendorCounts)
		} else {
			log.Println("│ Сохранено: 0")
		}

		db.UpdateProgress(ctx, tableName, chunkLastID)
		lastID = chunkLastID

		elapsed := time.Since(chunkStart).Seconds()
		rate := float64(len(records)) / elapsed
		log.Printf("│ Скорость чанка: %.0f IP/s | Всего сохранено: %d", rate, totalSaved)
	}
}

// =============================================================================
// MAIN
// =============================================================================

func main() {
	cfg := LoadConfig()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("╔══════════════════════════════════════════╗")
	log.Println("║  SCANNER v14 — HIGH-PERF RAW TLS        ║")
	log.Println("║  Dial: 1s | Read: 2s | Workers: 2000    ║")
	log.Printf("║  Concurrency: %-4d                       ║\n", cfg.Concurrency)
	log.Printf("║  Timeout: %-4.0fs                        ║\n", cfg.Timeout.Seconds())
	log.Println("╚══════════════════════════════════════════╝")

	ctx := context.Background()

	db, err := NewDB(cfg)
	if err != nil {
		log.Fatalf("DB init: %v", err)
	}
	defer db.Close()

	if err := db.Setup(ctx); err != nil {
		log.Fatalf("DB setup: %v", err)
	}

	tables, err := db.GetTables(ctx)
	if err != nil {
		log.Fatalf("Get tables: %v", err)
	}
	log.Printf("Таблиц: %d — %v", len(tables), tables)

	scanner := NewTLSScanner(cfg.Concurrency, cfg.Timeout, cfg.SpeedLogInterval)

	for i, table := range tables {
		log.Printf("[%d/%d] Обработка: %s", i+1, len(tables), table)
		if err := processTable(ctx, scanner, db, table, cfg.ChunkSize, cfg.Concurrency); err != nil {
			log.Printf("Ошибка: %v", err)
		}
	}

	stats := scanner.GetStats()
	log.Println("")
	log.Println("╔══════════════════════════════════════════╗")
	log.Printf("║ ИТОГО: %-30d ║\n", stats["total_scanned"])
	log.Printf("║ Найдено: %-27d ║\n", stats["total_found"])
	log.Printf("║ Скорость: %-25.0f IP/s ║\n", stats["rate"])
	log.Println("╚══════════════════════════════════════════╝")
}

func formatInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

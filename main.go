package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("your-secret-key-change-this")

const (
	StatusNotDone  = 1
	StatusPending  = 2
	StatusApproved = 3

	TypeDaily   = 1
	TypeWeekly  = 2
	TypeMonthly = 3

	RoleSuperAdmin = "super_admin"
	RoleChecker    = "checker"
	RoleWorker     = "worker"
)

type User struct {
	ID             int      `json:"userId"`
	Username       string   `json:"username"`
	Login          string   `json:"login"`
	Password       string   `json:"-"`
	Role           string   `json:"role"`
	FilialIDs      []int    `json:"filialIds,omitempty"`
	Categories     []string `json:"categories,omitempty"`
	NotificationID *string  `json:"notificationId,omitempty"`
	IsLogin        bool     `json:"isLogin"`
}

type Filial struct {
	ID         int      `json:"filialId"`
	Name       string   `json:"name"`
	Categories []string `json:"categories,omitempty"`
}

type Task struct {
	ID               int     `json:"taskId"`
	FilialID         int     `json:"filialId"`
	WorkerIDs        []int   `json:"workerIds,omitempty"`
	Task             string  `json:"task"`
	Type             int     `json:"type"`
	Status           int     `json:"status"`
	VideoURL         *string `json:"videoUrl"`
	SubmittedAt      *string `json:"submittedAt,omitempty"`
	SubmittedBy      *string `json:"submittedBy,omitempty"`
	Date             string  `json:"date"`
	Days             []int   `json:"days,omitempty"`
	Category         string  `json:"category"`
	NotificationTime string  `json:"notificationTime,omitempty"`
	OrderIndex       int     `json:"orderIndex"`
}

type Claims struct {
	UserID    int    `json:"userId"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	FilialIDs []int  `json:"filialIds,omitempty"`
	jwt.RegisteredClaims
}

func main() {
	initDB()

	go startScheduler()
	go startCleanup()
	go startNotificationScheduler()

	r := mux.NewRouter()

	// Auth
	r.HandleFunc("/api/auth/register", register).Methods("POST")
	r.HandleFunc("/api/auth/login", login).Methods("POST")
	r.HandleFunc("/api/auth/logout", authMiddleware(logout)).Methods("POST")
	r.HandleFunc("/api/auth/force-logout/{userId}", authMiddleware(forceLogout)).Methods("POST")

	// Tasks
	r.HandleFunc("/api/tasks", authMiddleware(getTasks)).Methods("GET")
	r.HandleFunc("/api/tasks/all", authMiddleware(getAllTasks)).Methods("GET")
	r.HandleFunc("/api/tasks", authMiddleware(createTask)).Methods("POST")
	r.HandleFunc("/api/tasks/{id}", authMiddleware(getTask)).Methods("GET")
	r.HandleFunc("/api/tasks/{id}", authMiddleware(updateTask)).Methods("PUT")
	r.HandleFunc("/api/tasks/{id}", authMiddleware(deleteTask)).Methods("DELETE")
	r.HandleFunc("/api/tasks/{id}/submit", authMiddleware(submitTask)).Methods("POST")
	r.HandleFunc("/api/tasks/{id}/check", authMiddleware(checkTask)).Methods("POST")
	r.HandleFunc("/api/tasks/reorder/{taskId}/{newPosition}", authMiddleware(reorderTask)).Methods("PUT")

	// Filials
	r.HandleFunc("/api/filials", authMiddleware(getFilials)).Methods("GET")
	r.HandleFunc("/api/filials", authMiddleware(createFilial)).Methods("POST")
	r.HandleFunc("/api/filials/{id}", authMiddleware(updateFilial)).Methods("PUT")
	r.HandleFunc("/api/filials/{id}", authMiddleware(deleteFilial)).Methods("DELETE")

	// Notifications
	r.HandleFunc("/api/notifications", authMiddleware(getNotifications)).Methods("GET")

	// Users
	r.HandleFunc("/api/users", authMiddleware(getUsers)).Methods("GET")
	r.HandleFunc("/api/users/{id}", authMiddleware(updateUser)).Methods("PUT")
	r.HandleFunc("/api/users/{id}", authMiddleware(deleteUser)).Methods("DELETE")

	// Debug
	r.HandleFunc("/api/debug/info", authMiddleware(getDebugInfo)).Methods("GET")

	// Static files
	r.PathPrefix("/videos/").Handler(http.StripPrefix("/videos/", http.FileServer(http.Dir("./videos"))))

	log.Println("Server started on :8000")
	log.Fatal(http.ListenAndServe(":8000", r))
}

func initDB() {
	os.MkdirAll("./db", 0755)
	os.MkdirAll("./videos", 0755)

	createMainDB()
	ensureTodayDB()

	log.Println("Database initialized successfully")
}

func createMainDB() {
	db, err := sql.Open("sqlite3", "./db/main.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTables := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		login TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		filial_ids TEXT,
		categories TEXT,
		notification_id TEXT,
		is_login INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS filials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		categories TEXT
	);

	CREATE TABLE IF NOT EXISTS task_templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task TEXT NOT NULL,
		type INTEGER NOT NULL,
		filial_ids TEXT NOT NULL,
		days TEXT,
		category TEXT NOT NULL,
		notification_time TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err = db.Exec(createTables)
	if err != nil {
		log.Fatal(err)
	}

	// Create super admin
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleSuperAdmin).Scan(&count)
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		db.Exec("INSERT INTO users (username, login, password_hash, role) VALUES (?, ?, ?, ?)",
			"Super Admin", "admin", string(hash), RoleSuperAdmin)
		log.Println("Super admin created: login=admin, password=admin123")
	}

	// Create filials
	db.QueryRow("SELECT COUNT(*) FROM filials").Scan(&count)
	if count == 0 {
		filials := map[string][]string{
			"Toshkent markaz": {"Shef Povar", "Admin", "Ofitsiant"},
			"Samarqand":       {"Shef Povar", "Admin"},
			"Buxoro":          {"Shef Povar", "Ofitsiant"},
			"Farg'ona":        {"Shef Povar", "Admin", "Ofitsiant"},
		}
		for name, categories := range filials {
			categoriesJSON, _ := json.Marshal(categories)
			db.Exec("INSERT INTO filials (name, categories) VALUES (?, ?)", name, string(categoriesJSON))
		}
	}
}

func getDBPath(date time.Time) string {
	return fmt.Sprintf("./db/tasks_%s.db", date.Format("2006-01-02"))
}

func ensureTodayDB() {
	ensureDBForDate(time.Now())
}

func ensureDBForDate(date time.Time) {
	dbPath := getDBPath(date)
	if _, err := os.Stat(dbPath); err == nil {
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Printf("Error creating DB for %s: %v\n", date.Format("2006-01-02"), err)
		return
	}
	defer db.Close()

	createTable := `
	CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filial_id INTEGER NOT NULL,
		worker_ids TEXT,
		task TEXT NOT NULL,
		type INTEGER NOT NULL,
		status INTEGER DEFAULT 1,
		video_url TEXT,
		submitted_at DATETIME,
		submitted_by TEXT,
		days TEXT,
		category TEXT NOT NULL,
		notification_time TEXT,
		order_index INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Printf("Error creating tasks table: %v\n", err)
		return
	}

	log.Printf("Created database for %s\n", date.Format("2006-01-02"))
}

func getMainDB() (*sql.DB, error) {
	return sql.Open("sqlite3", "./db/main.db")
}

func getTaskDB(date time.Time) (*sql.DB, error) {
	ensureDBForDate(date)
	return sql.Open("sqlite3", getDBPath(date))
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "Token yo'q",
			})
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "Noto'g'ri token",
			})
			return
		}

		r.Header.Set("UserID", strconv.Itoa(claims.UserID))
		r.Header.Set("Username", claims.Username)
		r.Header.Set("Role", claims.Role)
		if len(claims.FilialIDs) > 0 {
			filialIDsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(claims.FilialIDs)), ","), "[]")
			r.Header.Set("FilialIDs", filialIDsStr)
		}

		next(w, r)
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username       string   `json:"username"`
		Login          string   `json:"login"`
		Password       string   `json:"password"`
		Role           string   `json:"role"`
		FilialIDs      []int    `json:"filialIds"`
		Categories     []string `json:"categories"`
		NotificationID *string  `json:"notificationId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	db, _ := getMainDB()
	defer db.Close()

	categoriesJSON, _ := json.Marshal(req.Categories)
	filialIDsStr := ""
	if len(req.FilialIDs) > 0 {
		filialIDsStr = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.FilialIDs)), ","), "[]")
	}

	result, err := db.Exec("INSERT INTO users (username, login, password_hash, role, filial_ids, categories, notification_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
		req.Username, req.Login, string(hash), req.Role, filialIDsStr, string(categoriesJSON), req.NotificationID)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Login band",
		})
		return
	}

	id, _ := result.LastInsertId()
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"userId":  id,
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login          string  `json:"login"`
		Password       string  `json:"password"`
		NotificationID *string `json:"notificationId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	db, _ := getMainDB()
	defer db.Close()

	var user User
	var passwordHash string
	var categoriesStr, filialIDsStr sql.NullString
	var notificationID sql.NullString
	var isLogin int
	err := db.QueryRow("SELECT id, username, login, password_hash, role, filial_ids, categories, notification_id, is_login FROM users WHERE login = ?",
		req.Login).Scan(&user.ID, &user.Username, &user.Login, &passwordHash, &user.Role, &filialIDsStr, &categoriesStr, &notificationID, &isLogin)

	if err != nil {
		log.Printf("Login error: %v\n", err)
		respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "Login yoki parol noto'g'ri",
		})
		return
	}

	// Check if user is already logged in
	if isLogin == 1 {
		respondJSON(w, http.StatusConflict, map[string]interface{}{
			"success": false,
			"error":   "Siz allaqachon tizimga kirgansiz. Avval logout qiling.",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "Login yoki parol noto'g'ri",
		})
		return
	}

	// Parse categories
	if categoriesStr.Valid && categoriesStr.String != "" {
		json.Unmarshal([]byte(categoriesStr.String), &user.Categories)
	}

	// Parse filial IDs
	if filialIDsStr.Valid && filialIDsStr.String != "" {
		user.FilialIDs = parseFilialIDs(filialIDsStr.String)
	}

	// Update notification ID and login status
	if req.NotificationID != nil {
		db.Exec("UPDATE users SET notification_id = ?, is_login = 1 WHERE id = ?", *req.NotificationID, user.ID)
		user.NotificationID = req.NotificationID
	} else {
		db.Exec("UPDATE users SET is_login = 1 WHERE id = ?", user.ID)
	}
	user.IsLogin = true

	claims := &Claims{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		FilialIDs: user.FilialIDs,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"token":   tokenString,
		"user":    user,
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("UserID"))

	db, _ := getMainDB()
	defer db.Close()

	_, err := db.Exec("UPDATE users SET is_login = 0 WHERE id = ?", userID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Tizimdan chiqdingiz",
	})
}

func forceLogout(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Faqat super admin ruxsati",
		})
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]

	db, _ := getMainDB()
	defer db.Close()

	_, err := db.Exec("UPDATE users SET is_login = 0 WHERE id = ?", targetUserID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "User tizimdan chiqarildi",
	})
}

func getTasks(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	userID, _ := strconv.Atoi(r.Header.Get("UserID"))

	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now()
	} else {
		var err error
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			date = time.Now()
		}
	}

	db, err := getTaskDB(date)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Database xatosi",
		})
		return
	}
	defer db.Close()

	var query string
	var args []interface{}

	if role == RoleWorker {
		// Get user's filials and categories
		mainDB, _ := getMainDB()
		defer mainDB.Close()

		var filialIDsStr, categoriesStr sql.NullString
		err := mainDB.QueryRow("SELECT filial_ids, categories FROM users WHERE id = ?", userID).Scan(&filialIDsStr, &categoriesStr)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"error":   "User ma'lumotlari topilmadi",
			})
			return
		}

		var categories []string
		if categoriesStr.Valid && categoriesStr.String != "" {
			json.Unmarshal([]byte(categoriesStr.String), &categories)
		}

		var filialIDs []int
		if filialIDsStr.Valid && filialIDsStr.String != "" {
			filialIDs = parseFilialIDs(filialIDsStr.String)
		}

		if len(filialIDs) == 0 || len(categories) == 0 {
			// No filials or categories assigned
			respondJSON(w, http.StatusOK, map[string]interface{}{
				"success": true,
				"data":    []Task{},
			})
			return
		}

		// Build query for user's filials and categories
		filialPlaceholders := make([]string, len(filialIDs))
		categoryPlaceholders := make([]string, len(categories))

		for i, id := range filialIDs {
			filialPlaceholders[i] = "?"
			args = append(args, id)
		}

		for i, cat := range categories {
			categoryPlaceholders[i] = "?"
			args = append(args, cat)
		}

		query = fmt.Sprintf(`
			SELECT id, filial_id, worker_ids, task, type, status, video_url, submitted_at, submitted_by, days, category, notification_time, order_index 
			FROM tasks 
			WHERE filial_id IN (%s) AND category IN (%s) 
			ORDER BY order_index ASC
		`, strings.Join(filialPlaceholders, ","), strings.Join(categoryPlaceholders, ","))
	} else {
		query = "SELECT id, filial_id, worker_ids, task, type, status, video_url, submitted_at, submitted_by, days, category, notification_time, order_index FROM tasks ORDER BY order_index ASC"
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}
	defer rows.Close()

	tasks := []Task{}
	for rows.Next() {
		var t Task
		var daysStr, notifTime, workerIDsStr sql.NullString
		t.Date = date.Format("2006-01-02")
		rows.Scan(&t.ID, &t.FilialID, &workerIDsStr, &t.Task, &t.Type, &t.Status, &t.VideoURL, &t.SubmittedAt, &t.SubmittedBy, &daysStr, &t.Category, &notifTime, &t.OrderIndex)

		if daysStr.Valid && daysStr.String != "" {
			t.Days = parseDays(daysStr.String)
		}
		if notifTime.Valid {
			t.NotificationTime = notifTime.String
		}
		if workerIDsStr.Valid && workerIDsStr.String != "" {
			t.WorkerIDs = parseFilialIDs(workerIDsStr.String)
		}

		tasks = append(tasks, t)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    tasks,
	})
}

func getAllTasks(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Faqat super admin ruxsati",
		})
		return
	}

	mainDB, err := getMainDB()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Database xatosi",
		})
		return
	}
	defer mainDB.Close()

	rows, err := mainDB.Query("SELECT id, task, type, filial_ids, days, category, notification_time, created_at FROM task_templates ORDER BY created_at DESC")
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}
	defer rows.Close()

	type TaskTemplate struct {
		ID               int    `json:"templateId"`
		Task             string `json:"task"`
		Type             int    `json:"type"`
		FilialIDs        []int  `json:"filialIds"`
		Days             []int  `json:"days,omitempty"`
		Category         string `json:"category"`
		NotificationTime string `json:"notificationTime,omitempty"`
		CreatedAt        string `json:"createdAt"`
	}

	templates := []TaskTemplate{}
	for rows.Next() {
		var t TaskTemplate
		var filialIDsStr, daysStr, createdAt string
		var notifTime sql.NullString
		rows.Scan(&t.ID, &t.Task, &t.Type, &filialIDsStr, &daysStr, &t.Category, &notifTime, &createdAt)

		t.FilialIDs = parseFilialIDs(filialIDsStr)

		if daysStr != "" {
			t.Days = parseDays(daysStr)
		}
		if notifTime.Valid {
			t.NotificationTime = notifTime.String
		}

		t.CreatedAt = createdAt
		templates = append(templates, t)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    templates,
		"total":   len(templates),
	})
}

func createTask(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	var req struct {
		FilialIDs        []int  `json:"filialIds"`
		Task             string `json:"task"`
		Type             int    `json:"type"`
		Days             []int  `json:"days"`
		Category         string `json:"category"`
		NotificationTime string `json:"time"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	// Validate days
	if req.Type == TypeWeekly {
		for _, day := range req.Days {
			if day < 1 || day > 7 {
				respondJSON(w, http.StatusBadRequest, map[string]interface{}{
					"success": false,
					"error":   "Hafta kunlari 1-7 oralig'ida bo'lishi kerak",
				})
				return
			}
		}
	} else if req.Type == TypeMonthly {
		for _, day := range req.Days {
			if day < 1 || day > 31 {
				respondJSON(w, http.StatusBadRequest, map[string]interface{}{
					"success": false,
					"error":   "Oy kunlari 1-31 oralig'ida bo'lishi kerak",
				})
				return
			}
		}
	}

	mainDB, _ := getMainDB()
	defer mainDB.Close()

	filialIDsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.FilialIDs)), ","), "[]")
	daysStr := ""
	if len(req.Days) > 0 {
		daysStr = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.Days)), ","), "[]")
	}

	result, err := mainDB.Exec("INSERT INTO task_templates (task, type, filial_ids, days, category, notification_time) VALUES (?, ?, ?, ?, ?, ?)",
		req.Task, req.Type, filialIDsStr, daysStr, req.Category, req.NotificationTime)

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Template yaratishda xato",
		})
		return
	}

	templateID, _ := result.LastInsertId()

	// Create tasks for today if applicable
	created := 0
	if req.Type == TypeDaily {
		created = createTasksForDate(req.Task, req.Type, req.FilialIDs, req.Days, req.Category, req.NotificationTime, time.Now())
	} else if req.Type == TypeWeekly {
		today := int(time.Now().Weekday())
		if today == 0 {
			today = 7
		}
		for _, day := range req.Days {
			if day == today {
				created = createTasksForDate(req.Task, req.Type, req.FilialIDs, req.Days, req.Category, req.NotificationTime, time.Now())
				break
			}
		}
	} else if req.Type == TypeMonthly {
		today := time.Now().Day()
		for _, day := range req.Days {
			if day == today {
				created = createTasksForDate(req.Task, req.Type, req.FilialIDs, req.Days, req.Category, req.NotificationTime, time.Now())
				break
			}
		}
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"taskId":  templateID,
		"created": created,
	})
}

func getTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now()
	} else {
		date, _ = time.Parse("2006-01-02", dateStr)
	}

	db, _ := getTaskDB(date)
	defer db.Close()

	var task Task
	var daysStr, notifTime, workerIDsStr sql.NullString
	task.Date = date.Format("2006-01-02")
	err := db.QueryRow("SELECT id, filial_id, worker_ids, task, type, status, video_url, submitted_at, submitted_by, days, category, notification_time, order_index FROM tasks WHERE id = ?", id).
		Scan(&task.ID, &task.FilialID, &workerIDsStr, &task.Task, &task.Type, &task.Status, &task.VideoURL, &task.SubmittedAt, &task.SubmittedBy, &daysStr, &task.Category, &notifTime, &task.OrderIndex)

	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "Vazifa topilmadi",
		})
		return
	}

	if daysStr.Valid && daysStr.String != "" {
		task.Days = parseDays(daysStr.String)
	}
	if notifTime.Valid {
		task.NotificationTime = notifTime.String
	}
	if workerIDsStr.Valid && workerIDsStr.String != "" {
		task.WorkerIDs = parseFilialIDs(workerIDsStr.String)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    task,
	})
}

func updateTask(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Task             string  `json:"task"`
		Type             int     `json:"type"`
		Status           *int    `json:"status,omitempty"`
		FilialIDs        []int   `json:"filialIds,omitempty"`
		WorkerIDs        []int   `json:"workerIds,omitempty"`
		Days             []int   `json:"days,omitempty"`
		Category         string  `json:"category"`
		NotificationTime *string `json:"time,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	mainDB, _ := getMainDB()
	defer mainDB.Close()

	mainUpdateFields := []string{"task = ?", "type = ?", "category = ?"}
	mainArgs := []interface{}{req.Task, req.Type, req.Category}

	if len(req.FilialIDs) > 0 {
		filialIDsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.FilialIDs)), ","), "[]")
		mainUpdateFields = append(mainUpdateFields, "filial_ids = ?")
		mainArgs = append(mainArgs, filialIDsStr)
	}

	if len(req.Days) > 0 {
		daysStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.Days)), ","), "[]")
		mainUpdateFields = append(mainUpdateFields, "days = ?")
		mainArgs = append(mainArgs, daysStr)
	}

	if req.NotificationTime != nil {
		mainUpdateFields = append(mainUpdateFields, "notification_time = ?")
		mainArgs = append(mainArgs, *req.NotificationTime)
	}

	mainArgs = append(mainArgs, id)
	mainQuery := fmt.Sprintf("UPDATE task_templates SET %s WHERE id = ?", strings.Join(mainUpdateFields, ", "))

	_, err := mainDB.Exec(mainQuery, mainArgs...)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Template yangilashda xato",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Template yangilandi",
	})
}

func deleteTask(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	mainDB, _ := getMainDB()
	defer mainDB.Close()

	var taskName string
	err := mainDB.QueryRow("SELECT task FROM task_templates WHERE id = ?", id).Scan(&taskName)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "Template topilmadi",
		})
		return
	}

	_, err = mainDB.Exec("DELETE FROM task_templates WHERE id = ?", id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Template o'chirishda xato",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Template o'chirildi",
	})
}

func reorderTask(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Faqat super admin ruxsati",
		})
		return
	}

	vars := mux.Vars(r)
	taskID := vars["taskId"]
	newPosition, err := strconv.Atoi(vars["newPosition"])
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri pozitsiya",
		})
		return
	}

	db, _ := getTaskDB(time.Now())
	defer db.Close()

	// Get current task info
	var currentOrder int
	err = db.QueryRow("SELECT order_index FROM tasks WHERE id = ?", taskID).Scan(&currentOrder)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "Vazifa topilmadi",
		})
		return
	}

	// Update order indexes for ALL tasks
	if newPosition > currentOrder {
		// Moving down: decrement tasks between current and new position
		db.Exec("UPDATE tasks SET order_index = order_index - 1 WHERE order_index > ? AND order_index <= ?",
			currentOrder, newPosition)
	} else if newPosition < currentOrder {
		// Moving up: increment tasks between new and current position
		db.Exec("UPDATE tasks SET order_index = order_index + 1 WHERE order_index >= ? AND order_index < ?",
			newPosition, currentOrder)
	}

	// Set new position for the task
	_, err = db.Exec("UPDATE tasks SET order_index = ? WHERE id = ?", newPosition, taskID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Tartibni o'zgartirishda xato",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Vazifa tartibi o'zgartirildi",
	})
}

func submitTask(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleWorker {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	taskID := vars["id"]
	username := r.Header.Get("Username")

	r.ParseMultipartForm(100 << 20)
	file, handler, err := r.FormFile("video")
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Video topilmadi",
		})
		return
	}
	defer file.Close()

	today := time.Now().Format("2006-01-02")
	dirPath := filepath.Join("./videos", today)
	os.MkdirAll(dirPath, 0755)

	// Save temporary original file
	tempFilename := fmt.Sprintf("temp_%s_%s", taskID, handler.Filename)
	tempPath := filepath.Join(dirPath, tempFilename)

	tempFile, err := os.Create(tempPath)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Faylni saqlashda xato",
		})
		return
	}
	io.Copy(tempFile, file)
	tempFile.Close()

	// Resize video to 500x500
	filename := fmt.Sprintf("video%s_%s", taskID, handler.Filename)
	outputPath := filepath.Join(dirPath, filename)

	err = resizeVideo(tempPath, outputPath, 500, 500)
	if err != nil {
		log.Printf("Video o'lchamini o'zgartirishda xato: %v\n", err)
		// If resize fails, use original
		os.Rename(tempPath, outputPath)
	} else {
		// Remove temp file
		os.Remove(tempPath)
	}

	videoURL := fmt.Sprintf("/videos/%s/%s", today, filename)
	submittedAt := time.Now().Format(time.RFC3339)

	db, _ := getTaskDB(time.Now())
	defer db.Close()

	_, err = db.Exec("UPDATE tasks SET status = ?, video_url = ?, submitted_at = ?, submitted_by = ? WHERE id = ?",
		StatusPending, videoURL, submittedAt, username, taskID)

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"videoUrl":    videoURL,
		"submittedBy": username,
		"submittedAt": submittedAt,
	})
}

func resizeVideo(inputPath, outputPath string, width, height int) error {
	// Using ffmpeg to resize and crop video to exact dimensions
	cmd := exec.Command("ffmpeg",
		"-i", inputPath,
		"-vf", fmt.Sprintf("scale=%d:%d:force_original_aspect_ratio=increase,crop=%d:%d", width, height, width, height),
		"-c:a", "copy",
		"-y",
		outputPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("FFmpeg error: %s\n", string(output))
		return err
	}

	return nil
}

func checkTask(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleChecker {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	taskID := vars["id"]

	var req struct {
		Status int `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	db, _ := getTaskDB(time.Now())
	defer db.Close()

	_, err := db.Exec("UPDATE tasks SET status = ? WHERE id = ?", req.Status, taskID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func getNotifications(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleWorker {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("UserID"))

	// Get user's filials and categories
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	var filialIDsStr, categoriesStr sql.NullString
	err := mainDB.QueryRow("SELECT filial_ids, categories FROM users WHERE id = ?", userID).Scan(&filialIDsStr, &categoriesStr)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "User ma'lumotlari topilmadi",
		})
		return
	}

	var categories []string
	if categoriesStr.Valid && categoriesStr.String != "" {
		json.Unmarshal([]byte(categoriesStr.String), &categories)
	}

	var filialIDs []int
	if filialIDsStr.Valid && filialIDsStr.String != "" {
		filialIDs = parseFilialIDs(filialIDsStr.String)
	}

	if len(filialIDs) == 0 || len(categories) == 0 {
		// No filials or categories assigned
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    []Task{},
			"total":   0,
		})
		return
	}

	// Get today's tasks with status = 1 (not done)
	db, err := getTaskDB(time.Now())
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Database xatosi",
		})
		return
	}
	defer db.Close()

	// Build query for matching filials and categories
	filialPlaceholders := make([]string, len(filialIDs))
	categoryPlaceholders := make([]string, len(categories))
	args := []interface{}{StatusNotDone}

	for i, id := range filialIDs {
		filialPlaceholders[i] = "?"
		args = append(args, id)
	}

	for i, cat := range categories {
		categoryPlaceholders[i] = "?"
		args = append(args, cat)
	}

	query := fmt.Sprintf(`
		SELECT id, filial_id, worker_ids, task, type, status, video_url, submitted_at, submitted_by, days, category, notification_time, order_index 
		FROM tasks 
		WHERE status = ? AND filial_id IN (%s) AND category IN (%s)
		ORDER BY order_index ASC
	`, strings.Join(filialPlaceholders, ","), strings.Join(categoryPlaceholders, ","))

	rows, err := db.Query(query, args...)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}
	defer rows.Close()

	tasks := []Task{}
	for rows.Next() {
		var t Task
		var daysStr, notifTime, workerIDsStr sql.NullString
		t.Date = time.Now().Format("2006-01-02")
		rows.Scan(&t.ID, &t.FilialID, &workerIDsStr, &t.Task, &t.Type, &t.Status, &t.VideoURL, &t.SubmittedAt, &t.SubmittedBy, &daysStr, &t.Category, &notifTime, &t.OrderIndex)

		if daysStr.Valid && daysStr.String != "" {
			t.Days = parseDays(daysStr.String)
		}
		if notifTime.Valid {
			t.NotificationTime = notifTime.String
		}
		if workerIDsStr.Valid && workerIDsStr.String != "" {
			t.WorkerIDs = parseFilialIDs(workerIDsStr.String)
		}

		tasks = append(tasks, t)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    tasks,
		"total":   len(tasks),
	})
}

func getFilials(w http.ResponseWriter, r *http.Request) {
	db, _ := getMainDB()
	defer db.Close()

	rows, err := db.Query("SELECT id, name, categories FROM filials")
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}
	defer rows.Close()

	filials := []Filial{}
	for rows.Next() {
		var f Filial
		var categoriesStr sql.NullString
		rows.Scan(&f.ID, &f.Name, &categoriesStr)
		if categoriesStr.Valid && categoriesStr.String != "" {
			json.Unmarshal([]byte(categoriesStr.String), &f.Categories)
		}
		filials = append(filials, f)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    filials,
	})
}

func createFilial(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	var req struct {
		Name       string   `json:"name"`
		Categories []string `json:"categories"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	db, _ := getMainDB()
	defer db.Close()

	categoriesJSON, _ := json.Marshal(req.Categories)

	result, err := db.Exec("INSERT INTO filials (name, categories) VALUES (?, ?)", req.Name, string(categoriesJSON))
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	id, _ := result.LastInsertId()
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success":  true,
		"filialId": id,
	})
}

func updateFilial(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Name       string   `json:"name"`
		Categories []string `json:"categories"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	db, _ := getMainDB()
	defer db.Close()

	categoriesJSON, _ := json.Marshal(req.Categories)

	_, err := db.Exec("UPDATE filials SET name = ?, categories = ? WHERE id = ?", req.Name, string(categoriesJSON), id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func deleteFilial(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	db, _ := getMainDB()
	defer db.Close()

	// Check if filial has users (check if filial_ids contains this ID)
	var userCount int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE filial_ids LIKE ?", "%"+id+"%").Scan(&userCount)
	if userCount > 0 {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Bu filialni o'chirib bo'lmaydi, unga biriktirilgan userlar mavjud",
		})
		return
	}

	_, err := db.Exec("DELETE FROM filials WHERE id = ?", id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Filial o'chirildi",
	})
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	filialID := r.URL.Query().Get("filialId")

	db, _ := getMainDB()
	defer db.Close()

	query := "SELECT id, username, login, role, filial_ids, categories, notification_id, is_login FROM users WHERE 1=1"
	args := []interface{}{}

	if role != "" {
		query += " AND role = ?"
		args = append(args, role)
	}
	if filialID != "" {
		query += " AND filial_ids LIKE ?"
		args = append(args, "%"+filialID+"%")
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var u User
		var categoriesStr, filialIDsStr sql.NullString
		var notifID sql.NullString
		var isLogin int
		rows.Scan(&u.ID, &u.Username, &u.Login, &u.Role, &filialIDsStr, &categoriesStr, &notifID, &isLogin)

		if categoriesStr.Valid && categoriesStr.String != "" {
			json.Unmarshal([]byte(categoriesStr.String), &u.Categories)
		}
		if filialIDsStr.Valid && filialIDsStr.String != "" {
			u.FilialIDs = parseFilialIDs(filialIDsStr.String)
		}
		if notifID.Valid {
			u.NotificationID = &notifID.String
		}
		u.IsLogin = isLogin == 1

		users = append(users, u)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    users,
	})
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Username   string   `json:"username"`
		Role       string   `json:"role"`
		FilialIDs  []int    `json:"filialIds"`
		Categories []string `json:"categories"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	db, _ := getMainDB()
	defer db.Close()

	categoriesJSON, _ := json.Marshal(req.Categories)
	filialIDsStr := ""
	if len(req.FilialIDs) > 0 {
		filialIDsStr = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.FilialIDs)), ","), "[]")
	}

	_, err := db.Exec("UPDATE users SET username = ?, role = ?, filial_ids = ?, categories = ? WHERE id = ?",
		req.Username, req.Role, filialIDsStr, string(categoriesJSON), id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("Role")
	if role != RoleSuperAdmin {
		respondJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Ruxsat yo'q",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	db, _ := getMainDB()
	defer db.Close()

	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func startScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	var lastRun string

	for range ticker.C {
		now := time.Now()
		currentDay := now.Format("2006-01-02")

		if now.Hour() == 0 && now.Minute() == 0 && lastRun != currentDay {
			lastRun = currentDay
			log.Println("=== Starting daily tasks creation ===")

			ensureTodayDB()
			createDailyTasks()
			createWeeklyTasks()
			createMonthlyTasks()

			log.Println("=== Task creation completed ===")
		}
	}
}

func startCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	var lastCleanup string

	for range ticker.C {
		now := time.Now()
		currentDay := now.Format("2006-01-02")

		if now.Hour() == 1 && lastCleanup != currentDay {
			lastCleanup = currentDay
			log.Println("=== Starting cleanup ===")
			cleanupOldData()
			log.Println("=== Cleanup completed ===")
		}
	}
}

func startNotificationScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		checkAndSendNotifications()
	}
}

func checkAndSendNotifications() {
	now := time.Now()
	currentTime := now.Format("15:04")

	db, err := getTaskDB(now)
	if err != nil {
		return
	}
	defer db.Close()

	mainDB, _ := getMainDB()
	defer mainDB.Close()

	// Get tasks that need notification at current time
	rows, err := db.Query(`
		SELECT t.id, t.task, t.worker_ids, t.category, t.notification_time, t.filial_id
		FROM tasks t 
		WHERE t.notification_time = ? AND t.status = ?`,
		currentTime, StatusNotDone)

	if err != nil {
		log.Printf("Error querying tasks for notification: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var taskID, filialID int
		var taskName, category, notifTime, workerIDsStr string
		rows.Scan(&taskID, &taskName, &workerIDsStr, &category, &notifTime, &filialID)

		// Parse worker IDs
		workerIDs := parseFilialIDs(workerIDsStr)

		// Send notification to all workers for this task
		for _, workerID := range workerIDs {
			var notificationID sql.NullString
			err := mainDB.QueryRow("SELECT notification_id FROM users WHERE id = ? AND is_login = 1", workerID).Scan(&notificationID)

			if err == nil && notificationID.Valid && notificationID.String != "" {
				sendPushNotification(notificationID.String, taskName, category)
				log.Printf("Notification sent for task %d to worker %d\n", taskID, workerID)
			}
		}
	}
}

func sendPushNotification(notificationID, taskName, category string) {
	// This is a placeholder function
	// Implement actual push notification logic here
	// You would typically use Firebase Cloud Messaging (FCM) or similar service
	log.Printf("Sending notification to %s: Task '%s' (Category: %s)\n", notificationID, taskName, category)
}

func createDailyTasks() {
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	rows, err := mainDB.Query("SELECT task, filial_ids, category, notification_time FROM task_templates WHERE type = ?", TypeDaily)
	if err != nil {
		log.Printf("Error loading daily templates: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var task, filialIDs, category string
		var notifTime sql.NullString
		rows.Scan(&task, &filialIDs, &category, &notifTime)

		ids := parseFilialIDs(filialIDs)
		notifTimeStr := ""
		if notifTime.Valid {
			notifTimeStr = notifTime.String
		}
		created := createTasksForDate(task, TypeDaily, ids, nil, category, notifTimeStr, time.Now())
		log.Printf("Daily task '%s': created %d tasks\n", task, created)
	}
}

func createWeeklyTasks() {
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	rows, err := mainDB.Query("SELECT task, filial_ids, days, category, notification_time FROM task_templates WHERE type = ?", TypeWeekly)
	if err != nil {
		log.Printf("Error loading weekly templates: %v\n", err)
		return
	}
	defer rows.Close()

	today := int(time.Now().Weekday())
	if today == 0 {
		today = 7
	}

	for rows.Next() {
		var task, filialIDs, daysStr, category string
		var notifTime sql.NullString
		rows.Scan(&task, &filialIDs, &daysStr, &category, &notifTime)

		days := parseDays(daysStr)

		shouldCreate := false
		for _, day := range days {
			if day == today {
				shouldCreate = true
				break
			}
		}

		if shouldCreate {
			ids := parseFilialIDs(filialIDs)
			notifTimeStr := ""
			if notifTime.Valid {
				notifTimeStr = notifTime.String
			}
			created := createTasksForDate(task, TypeWeekly, ids, days, category, notifTimeStr, time.Now())
			log.Printf("Weekly task '%s': created %d tasks\n", task, created)
		}
	}
}

func createMonthlyTasks() {
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	rows, err := mainDB.Query("SELECT task, filial_ids, days, category, notification_time FROM task_templates WHERE type = ?", TypeMonthly)
	if err != nil {
		log.Printf("Error loading monthly templates: %v\n", err)
		return
	}
	defer rows.Close()

	today := time.Now().Day()

	for rows.Next() {
		var task, filialIDs, daysStr, category string
		var notifTime sql.NullString
		rows.Scan(&task, &filialIDs, &daysStr, &category, &notifTime)

		days := parseDays(daysStr)

		shouldCreate := false
		for _, day := range days {
			if day == today {
				shouldCreate = true
				break
			}
		}

		if shouldCreate {
			ids := parseFilialIDs(filialIDs)
			notifTimeStr := ""
			if notifTime.Valid {
				notifTimeStr = notifTime.String
			}
			created := createTasksForDate(task, TypeMonthly, ids, days, category, notifTimeStr, time.Now())
			log.Printf("Monthly task '%s': created %d tasks\n", task, created)
		}
	}
}

func parseFilialIDs(filialIDs string) []int {
	ids := strings.Split(filialIDs, ",")
	result := []int{}
	for _, id := range ids {
		val, _ := strconv.Atoi(strings.TrimSpace(id))
		if val > 0 {
			result = append(result, val)
		}
	}
	return result
}

func parseDays(daysStr string) []int {
	if daysStr == "" {
		return []int{}
	}

	days := strings.Split(daysStr, ",")
	result := []int{}
	for _, day := range days {
		val, _ := strconv.Atoi(strings.TrimSpace(day))
		if val > 0 {
			result = append(result, val)
		}
	}
	return result
}

func createTasksForDate(task string, taskType int, filialIDs []int, days []int, category, notificationTime string, date time.Time) int {
	taskDB, err := getTaskDB(date)
	if err != nil {
		log.Printf("Error opening task DB: %v\n", err)
		return 0
	}
	defer taskDB.Close()

	mainDB, _ := getMainDB()
	defer mainDB.Close()

	created := 0
	daysStr := ""
	if len(days) > 0 {
		daysStr = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(days)), ","), "[]")
	}

	for _, filialID := range filialIDs {
		// Get workers with matching category for this filial
		rows, err := mainDB.Query(`
			SELECT id FROM users 
			WHERE role = ? AND filial_ids LIKE ? AND categories LIKE ?`,
			RoleWorker, "%"+strconv.Itoa(filialID)+"%", "%"+category+"%")

		if err != nil {
			log.Printf("Workers not found for filial %d: %v\n", filialID, err)
			continue
		}

		workerIDs := []int{}
		for rows.Next() {
			var workerID int
			rows.Scan(&workerID)
			workerIDs = append(workerIDs, workerID)
		}
		rows.Close()

		if len(workerIDs) == 0 {
			log.Printf("No workers with category '%s' found for filial %d\n", category, filialID)
			continue
		}

		// Check if task already exists for this filial and category
		var existingID int
		err = taskDB.QueryRow("SELECT id FROM tasks WHERE filial_id = ? AND task = ? AND category = ?",
			filialID, task, category).Scan(&existingID)

		if err == nil {
			log.Printf("Task already exists for filial %d and category %s\n", filialID, category)
			continue
		}

		// Get max order_index for this filial and category
		var maxOrder int
		taskDB.QueryRow("SELECT COALESCE(MAX(order_index), 0) FROM tasks WHERE filial_id = ? AND category = ?",
			filialID, category).Scan(&maxOrder)

		// Convert worker IDs to string
		workerIDsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(workerIDs)), ","), "[]")

		result, err := taskDB.Exec(`
			INSERT INTO tasks (filial_id, worker_ids, task, type, status, days, category, notification_time, order_index) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			filialID, workerIDsStr, task, taskType, StatusNotDone, daysStr, category, notificationTime, maxOrder+1)

		if err != nil {
			log.Printf("Error creating task (filial=%d, category=%s): %v\n", filialID, category, err)
			continue
		}

		taskID, _ := result.LastInsertId()
		log.Printf("✓ Created task ID %d for filial %d (category %s, workers: %v)\n", taskID, filialID, category, workerIDs)
		created++
	}

	return created
}

func cleanupOldData() {
	cutoffDate := time.Now().AddDate(0, 0, -5)
	log.Printf("Cleaning data older than %s\n", cutoffDate.Format("2006-01-02"))

	dbFiles, err := filepath.Glob("./db/tasks_*.db")
	if err != nil {
		log.Printf("Error listing DB files: %v\n", err)
		return
	}

	deletedDBs := 0
	for _, dbFile := range dbFiles {
		filename := filepath.Base(dbFile)
		dateStr := strings.TrimPrefix(filename, "tasks_")
		dateStr = strings.TrimSuffix(dateStr, ".db")

		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}

		if fileDate.Before(cutoffDate) {
			os.Remove(dbFile)
			log.Printf("✓ Deleted database: %s\n", filename)
			deletedDBs++
		}
	}

	videoDirs, err := os.ReadDir("./videos")
	if err != nil {
		log.Printf("Error listing video dirs: %v\n", err)
		return
	}

	deletedVideos := 0
	for _, entry := range videoDirs {
		if !entry.IsDir() {
			continue
		}

		dirDate, err := time.Parse("2006-01-02", entry.Name())
		if err != nil {
			continue
		}

		if dirDate.Before(cutoffDate) {
			dirPath := filepath.Join("./videos", entry.Name())
			os.RemoveAll(dirPath)
			log.Printf("✓ Deleted videos: %s\n", entry.Name())
			deletedVideos++
		}
	}

	log.Printf("Cleanup summary: %d databases, %d video folders deleted\n", deletedDBs, deletedVideos)
}

func getDebugInfo(w http.ResponseWriter, r *http.Request) {
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	var workerCount, checkerCount, adminCount int
	mainDB.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleWorker).Scan(&workerCount)
	mainDB.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleChecker).Scan(&checkerCount)
	mainDB.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleSuperAdmin).Scan(&adminCount)

	var templateCount int
	mainDB.QueryRow("SELECT COUNT(*) FROM task_templates").Scan(&templateCount)

	rows, _ := mainDB.Query("SELECT id, username, login, filial_ids, categories FROM users WHERE role = ?", RoleWorker)
	defer rows.Close()

	workers := []map[string]interface{}{}
	for rows.Next() {
		var id int
		var username, login, filialIDsStr string
		var categoriesStr sql.NullString
		rows.Scan(&id, &username, &login, &filialIDsStr, &categoriesStr)

		var categories []string
		if categoriesStr.Valid && categoriesStr.String != "" {
			json.Unmarshal([]byte(categoriesStr.String), &categories)
		}

		filialIDs := parseFilialIDs(filialIDsStr)

		workers = append(workers, map[string]interface{}{
			"id":         id,
			"username":   username,
			"login":      login,
			"filialIds":  filialIDs,
			"categories": categories,
		})
	}

	todayDB, _ := getTaskDB(time.Now())
	defer todayDB.Close()

	var taskTotal, taskNotDone, taskPending, taskApproved int
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&taskTotal)
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks WHERE status = ?", StatusNotDone).Scan(&taskNotDone)
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks WHERE status = ?", StatusPending).Scan(&taskPending)
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks WHERE status = ?", StatusApproved).Scan(&taskApproved)

	dbFiles, _ := filepath.Glob("./db/tasks_*.db")
	dbDates := []string{}
	for _, f := range dbFiles {
		name := filepath.Base(f)
		date := strings.TrimPrefix(name, "tasks_")
		date = strings.TrimSuffix(date, ".db")
		dbDates = append(dbDates, date)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"users": map[string]interface{}{
				"workers":    workerCount,
				"checkers":   checkerCount,
				"admins":     adminCount,
				"workerList": workers,
			},
			"templates": templateCount,
			"todayTasks": map[string]interface{}{
				"total":    taskTotal,
				"notDone":  taskNotDone,
				"pending":  taskPending,
				"approved": taskApproved,
			},
			"databases": map[string]interface{}{
				"count": len(dbDates),
				"dates": dbDates,
			},
			"currentDate": time.Now().Format("2006-01-02"),
		},
	})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

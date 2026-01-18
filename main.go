package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
	ID       int    `json:"userId"`
	Username string `json:"username"`
	Login    string `json:"login"`
	Password string `json:"-"`
	Role     string `json:"role"`
	FilialID *int   `json:"filialId,omitempty"`
}

type Filial struct {
	ID   int    `json:"filialId"`
	Name string `json:"name"`
}

type Task struct {
	ID          int     `json:"taskId"`
	FilialID    int     `json:"filialId"`
	WorkerID    *int    `json:"workerId,omitempty"`
	Task        string  `json:"task"`
	Type        int     `json:"type"`
	Status      int     `json:"status"`
	VideoURL    *string `json:"videoUrl"`
	SubmittedAt *string `json:"submittedAt,omitempty"`
	Date        string  `json:"date"`
	Days        []int   `json:"days,omitempty"`
}

type Claims struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
	Role     string `json:"role"`
	FilialID *int   `json:"filialId,omitempty"`
	jwt.RegisteredClaims
}

func main() {
	initDB()

	go startScheduler()
	go startCleanup()

	r := mux.NewRouter()

	// Auth
	r.HandleFunc("/api/auth/register", register).Methods("POST")
	r.HandleFunc("/api/auth/login", login).Methods("POST")

	// Tasks
	r.HandleFunc("/api/tasks", authMiddleware(getTasks)).Methods("GET")
	r.HandleFunc("/api/tasks/all", authMiddleware(getAllTasks)).Methods("GET")
	r.HandleFunc("/api/tasks", authMiddleware(createTask)).Methods("POST")
	r.HandleFunc("/api/tasks/{id}", authMiddleware(getTask)).Methods("GET")
	r.HandleFunc("/api/tasks/{id}", authMiddleware(updateTask)).Methods("PUT")
	r.HandleFunc("/api/tasks/{id}", authMiddleware(deleteTask)).Methods("DELETE")
	r.HandleFunc("/api/tasks/{id}/submit", authMiddleware(submitTask)).Methods("POST")
	r.HandleFunc("/api/tasks/{id}/check", authMiddleware(checkTask)).Methods("POST")

	// Filials
	r.HandleFunc("/api/filials", authMiddleware(getFilials)).Methods("GET")
	r.HandleFunc("/api/filials", authMiddleware(createFilial)).Methods("POST")

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
	// Create database directory structure
	os.MkdirAll("./db", 0755)
	os.MkdirAll("./videos", 0755)

	// Create main database for users and filials
	createMainDB()

	// Create today's task database if not exists
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
		filial_id INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS filials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS task_templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task TEXT NOT NULL,
		type INTEGER NOT NULL,
		filial_ids TEXT NOT NULL,
		days TEXT,
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
		filials := []string{"Toshkent markaz", "Samarqand", "Buxoro", "Farg'ona"}
		for _, name := range filials {
			db.Exec("INSERT INTO filials (name) VALUES (?)", name)
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
		return // DB already exists
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
		worker_id INTEGER,
		task TEXT NOT NULL,
		type INTEGER NOT NULL,
		status INTEGER DEFAULT 1,
		video_url TEXT,
		submitted_at DATETIME,
		days TEXT,
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
		r.Header.Set("Role", claims.Role)
		if claims.FilialID != nil {
			r.Header.Set("FilialID", strconv.Itoa(*claims.FilialID))
		}

		next(w, r)
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Login    string `json:"login"`
		Password string `json:"password"`
		Role     string `json:"role"`
		FilialID *int   `json:"filialId"`
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

	result, err := db.Exec("INSERT INTO users (username, login, password_hash, role, filial_id) VALUES (?, ?, ?, ?, ?)",
		req.Username, req.Login, string(hash), req.Role, req.FilialID)
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
		Login    string `json:"login"`
		Password string `json:"password"`
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
	err := db.QueryRow("SELECT id, username, login, password_hash, role, filial_id FROM users WHERE login = ?",
		req.Login).Scan(&user.ID, &user.Username, &user.Login, &passwordHash, &user.Role, &user.FilialID)

	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "Login yoki parol noto'g'ri",
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

	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		FilialID: user.FilialID,
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
		query = "SELECT id, filial_id, worker_id, task, type, status, video_url, submitted_at, days FROM tasks WHERE worker_id = ?"
		args = []interface{}{userID}
	} else {
		// Super admin va checker barcha tasklarni ko'radi
		query = "SELECT id, filial_id, worker_id, task, type, status, video_url, submitted_at, days FROM tasks"
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
		var daysStr sql.NullString
		t.Date = date.Format("2006-01-02")
		rows.Scan(&t.ID, &t.FilialID, &t.WorkerID, &t.Task, &t.Type, &t.Status, &t.VideoURL, &t.SubmittedAt, &daysStr)

		// Parse days if available
		if daysStr.Valid && daysStr.String != "" {
			t.Days = parseDays(daysStr.String)
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

	rows, err := mainDB.Query("SELECT id, task, type, filial_ids, days, created_at FROM task_templates ORDER BY created_at DESC")
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}
	defer rows.Close()

	type TaskTemplate struct {
		ID        int    `json:"templateId"`
		Task      string `json:"task"`
		Type      int    `json:"type"`
		FilialIDs []int  `json:"filialIds"`
		Days      []int  `json:"days,omitempty"`
		CreatedAt string `json:"createdAt"`
	}

	templates := []TaskTemplate{}
	for rows.Next() {
		var t TaskTemplate
		var filialIDsStr, daysStr, createdAt string
		rows.Scan(&t.ID, &t.Task, &t.Type, &filialIDsStr, &daysStr, &createdAt)

		// Parse filial IDs
		t.FilialIDs = parseFilialIDs(filialIDsStr)

		// Parse days if available
		if daysStr != "" {
			t.Days = parseDays(daysStr)
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
		FilialIDs []int  `json:"filialIds"`
		Task      string `json:"task"`
		Type      int    `json:"type"`
		Days      []int  `json:"days"` // Yangi field
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	// Validate days based on task type
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

	// Save template
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	filialIDsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.FilialIDs)), ","), "[]")

	// Convert days to string
	daysStr := ""
	if len(req.Days) > 0 {
		daysStr = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.Days)), ","), "[]")
	}

	result, err := mainDB.Exec("INSERT INTO task_templates (task, type, filial_ids, days) VALUES (?, ?, ?, ?)",
		req.Task, req.Type, filialIDsStr, daysStr)

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
		created = createTasksForDate(req.Task, req.Type, req.FilialIDs, req.Days, time.Now())
	} else if req.Type == TypeWeekly {
		// Check if today matches any of the specified days
		today := int(time.Now().Weekday())
		if today == 0 {
			today = 7 // Sunday = 7
		}
		for _, day := range req.Days {
			if day == today {
				created = createTasksForDate(req.Task, req.Type, req.FilialIDs, req.Days, time.Now())
				break
			}
		}
	} else if req.Type == TypeMonthly {
		// Check if today matches any of the specified days
		today := time.Now().Day()
		for _, day := range req.Days {
			if day == today {
				created = createTasksForDate(req.Task, req.Type, req.FilialIDs, req.Days, time.Now())
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
	var daysStr sql.NullString
	task.Date = date.Format("2006-01-02")
	err := db.QueryRow("SELECT id, filial_id, worker_id, task, type, status, video_url, submitted_at, days FROM tasks WHERE id = ?", id).
		Scan(&task.ID, &task.FilialID, &task.WorkerID, &task.Task, &task.Type, &task.Status, &task.VideoURL, &task.SubmittedAt, &daysStr)

	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "Vazifa topilmadi",
		})
		return
	}

	// Parse days if available
	if daysStr.Valid && daysStr.String != "" {
		task.Days = parseDays(daysStr.String)
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
		Task      string `json:"task"`
		Type      int    `json:"type"`
		Status    *int   `json:"status,omitempty"`
		FilialIDs []int  `json:"filialIds,omitempty"`
		WorkerID  *int   `json:"workerId,omitempty"`
		Days      []int  `json:"days,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Noto'g'ri ma'lumot",
		})
		return
	}

	// Validate days based on task type
	if len(req.Days) > 0 {
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
	}

	// Update main database template
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	mainUpdateFields := []string{"task = ?", "type = ?"}
	mainArgs := []interface{}{req.Task, req.Type}

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

	// Update today's task database if date is provided or default to today
	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now()
	} else {
		date, _ = time.Parse("2006-01-02", dateStr)
	}

	taskDB, _ := getTaskDB(date)
	defer taskDB.Close()

	// Build dynamic update query for task database
	taskUpdateFields := []string{"task = ?", "type = ?"}
	taskArgs := []interface{}{req.Task, req.Type}

	if req.Status != nil {
		taskUpdateFields = append(taskUpdateFields, "status = ?")
		taskArgs = append(taskArgs, *req.Status)
	}

	if req.WorkerID != nil {
		taskUpdateFields = append(taskUpdateFields, "worker_id = ?")
		taskArgs = append(taskArgs, *req.WorkerID)
	}

	if len(req.Days) > 0 {
		daysStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(req.Days)), ","), "[]")
		taskUpdateFields = append(taskUpdateFields, "days = ?")
		taskArgs = append(taskArgs, daysStr)
	}

	// Update all tasks with matching template task name
	taskArgs = append(taskArgs, req.Task)
	taskQuery := fmt.Sprintf("UPDATE tasks SET %s WHERE task = ?", strings.Join(taskUpdateFields, ", "))

	_, err = taskDB.Exec(taskQuery, taskArgs...)
	if err != nil {
		log.Printf("Task yangilashda xato: %v\n", err)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Template va tegishli tasklar yangilandi",
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

	// Delete from main database (task_templates)
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	// Get task name before deleting to remove from daily databases
	var taskName string
	err := mainDB.QueryRow("SELECT task FROM task_templates WHERE id = ?", id).Scan(&taskName)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "Template topilmadi",
		})
		return
	}

	// Delete from main database
	_, err = mainDB.Exec("DELETE FROM task_templates WHERE id = ?", id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Template o'chirishda xato",
		})
		return
	}

	// Delete from today's task database
	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now()
	} else {
		date, _ = time.Parse("2006-01-02", dateStr)
	}

	taskDB, _ := getTaskDB(date)
	defer taskDB.Close()

	// Delete all tasks with this task name
	_, err = taskDB.Exec("DELETE FROM tasks WHERE task = ?", taskName)
	if err != nil {
		log.Printf("Kunlik tasklar o'chirishda xato: %v\n", err)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Template va tegishli tasklar o'chirildi",
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

	filename := fmt.Sprintf("video%s_%s", taskID, handler.Filename)
	filePath := filepath.Join(dirPath, filename)

	dst, err := os.Create(filePath)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Faylni saqlashda xato",
		})
		return
	}
	defer dst.Close()

	io.Copy(dst, file)

	videoURL := fmt.Sprintf("/videos/%s/%s", today, filename)

	db, _ := getTaskDB(time.Now())
	defer db.Close()

	_, err = db.Exec("UPDATE tasks SET status = ?, video_url = ?, submitted_at = ? WHERE id = ?",
		StatusPending, videoURL, time.Now().Format(time.RFC3339), taskID)

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Server xatosi",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"videoUrl": videoURL,
	})
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

func getFilials(w http.ResponseWriter, r *http.Request) {
	db, _ := getMainDB()
	defer db.Close()

	rows, err := db.Query("SELECT id, name FROM filials")
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
		rows.Scan(&f.ID, &f.Name)
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
		Name string `json:"name"`
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

	result, err := db.Exec("INSERT INTO filials (name) VALUES (?)", req.Name)
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

func getUsers(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	filialID := r.URL.Query().Get("filialId")

	db, _ := getMainDB()
	defer db.Close()

	query := "SELECT id, username, login, role, filial_id FROM users WHERE 1=1"
	args := []interface{}{}

	if role != "" {
		query += " AND role = ?"
		args = append(args, role)
	}
	if filialID != "" {
		query += " AND filial_id = ?"
		args = append(args, filialID)
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
		rows.Scan(&u.ID, &u.Username, &u.Login, &u.Role, &u.FilialID)
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
		Username string `json:"username"`
		Role     string `json:"role"`
		FilialID *int   `json:"filialId"`
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

	_, err := db.Exec("UPDATE users SET username = ?, role = ?, filial_id = ? WHERE id = ?",
		req.Username, req.Role, req.FilialID, id)
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

func createDailyTasks() {
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	rows, err := mainDB.Query("SELECT task, filial_ids FROM task_templates WHERE type = ?", TypeDaily)
	if err != nil {
		log.Printf("Error loading daily templates: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var task, filialIDs string
		rows.Scan(&task, &filialIDs)

		ids := parseFilialIDs(filialIDs)
		created := createTasksForDate(task, TypeDaily, ids, nil, time.Now())
		log.Printf("Daily task '%s': created %d tasks\n", task, created)
	}
}

func createWeeklyTasks() {
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	rows, err := mainDB.Query("SELECT task, filial_ids, days FROM task_templates WHERE type = ?", TypeWeekly)
	if err != nil {
		log.Printf("Error loading weekly templates: %v\n", err)
		return
	}
	defer rows.Close()

	today := int(time.Now().Weekday())
	if today == 0 {
		today = 7 // Sunday = 7
	}

	for rows.Next() {
		var task, filialIDs, daysStr string
		rows.Scan(&task, &filialIDs, &daysStr)

		days := parseDays(daysStr)

		// Check if today is in the allowed days
		shouldCreate := false
		for _, day := range days {
			if day == today {
				shouldCreate = true
				break
			}
		}

		if shouldCreate {
			ids := parseFilialIDs(filialIDs)
			created := createTasksForDate(task, TypeWeekly, ids, days, time.Now())
			log.Printf("Weekly task '%s': created %d tasks\n", task, created)
		}
	}
}

func createMonthlyTasks() {
	mainDB, _ := getMainDB()
	defer mainDB.Close()

	rows, err := mainDB.Query("SELECT task, filial_ids, days FROM task_templates WHERE type = ?", TypeMonthly)
	if err != nil {
		log.Printf("Error loading monthly templates: %v\n", err)
		return
	}
	defer rows.Close()

	today := time.Now().Day()

	for rows.Next() {
		var task, filialIDs, daysStr string
		rows.Scan(&task, &filialIDs, &daysStr)

		days := parseDays(daysStr)

		// Check if today is in the allowed days
		shouldCreate := false
		for _, day := range days {
			if day == today {
				shouldCreate = true
				break
			}
		}

		if shouldCreate {
			ids := parseFilialIDs(filialIDs)
			created := createTasksForDate(task, TypeMonthly, ids, days, time.Now())
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

func createTasksForDate(task string, taskType int, filialIDs []int, days []int, date time.Time) int {
	taskDB, err := getTaskDB(date)
	if err != nil {
		log.Printf("Error opening task DB: %v\n", err)
		return 0
	}
	defer taskDB.Close()

	mainDB, _ := getMainDB()
	defer mainDB.Close()

	created := 0

	// Convert days to string for storage
	daysStr := ""
	if len(days) > 0 {
		daysStr = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(days)), ","), "[]")
	}

	for _, filialID := range filialIDs {
		var workerID int
		err := mainDB.QueryRow("SELECT id FROM users WHERE role = ? AND filial_id = ?", RoleWorker, filialID).Scan(&workerID)

		if err != nil {
			log.Printf("Worker not found for filial %d: %v\n", filialID, err)
			continue
		}

		// Check if task already exists
		var existingID int
		err = taskDB.QueryRow("SELECT id FROM tasks WHERE worker_id = ? AND task = ?", workerID, task).Scan(&existingID)

		if err == nil {
			log.Printf("Task already exists for worker %d\n", workerID)
			continue
		}

		result, err := taskDB.Exec("INSERT INTO tasks (filial_id, worker_id, task, type, status, days) VALUES (?, ?, ?, ?, ?, ?)",
			filialID, workerID, task, taskType, StatusNotDone, daysStr)

		if err != nil {
			log.Printf("Error creating task (filial=%d, worker=%d): %v\n", filialID, workerID, err)
			continue
		}

		taskID, _ := result.LastInsertId()
		log.Printf("✓ Created task ID %d for worker %d (filial %d)\n", taskID, workerID, filialID)
		created++
	}

	return created
}

func cleanupOldData() {
	cutoffDate := time.Now().AddDate(0, 0, -5)
	log.Printf("Cleaning data older than %s\n", cutoffDate.Format("2006-01-02"))

	// Clean old task databases
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

	// Clean old videos
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

	// Count users
	var workerCount, checkerCount, adminCount int
	mainDB.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleWorker).Scan(&workerCount)
	mainDB.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleChecker).Scan(&checkerCount)
	mainDB.QueryRow("SELECT COUNT(*) FROM users WHERE role = ?", RoleSuperAdmin).Scan(&adminCount)

	// Count templates
	var templateCount int
	mainDB.QueryRow("SELECT COUNT(*) FROM task_templates").Scan(&templateCount)

	// Get workers
	rows, _ := mainDB.Query("SELECT id, username, login, filial_id FROM users WHERE role = ?", RoleWorker)
	defer rows.Close()

	workers := []map[string]interface{}{}
	for rows.Next() {
		var id, filialID int
		var username, login string
		rows.Scan(&id, &username, &login, &filialID)
		workers = append(workers, map[string]interface{}{
			"id":       id,
			"username": username,
			"login":    login,
			"filialId": filialID,
		})
	}

	// Get templates
	rows2, _ := mainDB.Query("SELECT id, task, type, filial_ids, days FROM task_templates")
	defer rows2.Close()

	templates := []map[string]interface{}{}
	for rows2.Next() {
		var id, taskType int
		var task, filialIDs, daysStr string
		rows2.Scan(&id, &task, &taskType, &filialIDs, &daysStr)
		templates = append(templates, map[string]interface{}{
			"id":        id,
			"task":      task,
			"type":      taskType,
			"filialIds": filialIDs,
			"days":      daysStr,
		})
	}

	// Count today's tasks
	todayDB, _ := getTaskDB(time.Now())
	defer todayDB.Close()

	var taskTotal, taskNotDone, taskPending, taskApproved int
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&taskTotal)
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks WHERE status = ?", StatusNotDone).Scan(&taskNotDone)
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks WHERE status = ?", StatusPending).Scan(&taskPending)
	todayDB.QueryRow("SELECT COUNT(*) FROM tasks WHERE status = ?", StatusApproved).Scan(&taskApproved)

	// List all DB files
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
			"templates": map[string]interface{}{
				"count": templateCount,
				"list":  templates,
			},
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

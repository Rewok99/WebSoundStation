package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
)

var db *sql.DB
var sessionID int

type Track struct {
	TrackName       string
	ArtistNickname  string
	Genre           string
	CloudStorageURL string
	Status          string
}

func initDB() {
	var err error
	connStr := "user=postgres dbname=label_db password=12345 sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to PostgreSQL!")
}

// Хеширование пароля
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Проверка пароля
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func authenticate(email, password string) bool {
	var storedPassword string
	err := db.QueryRow("SELECT password, id FROM users WHERE email = $1", email).Scan(&storedPassword, &sessionID)
	if err != nil {
		fmt.Println("Ошибка получения пользователя:", err)
		return false
	}

	// Сравнение хешированного пароля
	return checkPasswordHash(password, storedPassword)
}

// Middleware для проверки авторизации
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sessionID == 0 { // Если пользователь не авторизован
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// Обработчик выхода
func logout(w http.ResponseWriter, r *http.Request) {
	// Завершаем сессию (сбрасываем sessionID)
	sessionID = 0
	// Перенаправляем на главную страницу
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func home_page(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/home_page.html")
	if err != nil {
		http.Error(w, "Ошибка при загрузке шаблона", http.StatusInternalServerError)
		return
	}

	// Передаем в шаблон информацию о том, выполнен ли вход
	tmpl.Execute(w, map[string]interface{}{
		"IsLoggedIn": sessionID != 0, // Если sessionID не равен 0, то пользователь авторизован
	})
}

func login_page(w http.ResponseWriter, r *http.Request) {
	var errorMsg string

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Проверяем авторизацию
		if authenticate(email, password) {
			// Успешная авторизация
			http.Redirect(w, r, "/main/", http.StatusSeeOther)
			return
		} else {
			// Неудачная авторизация
			errorMsg = "Неверный email или пароль"
			log.Println("Ошибка авторизации: неверный email или пароль")
		}
	}

	// Загрузка шаблона
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Ошибка при загрузке шаблона", http.StatusInternalServerError)
		return
	}
	// Передаем сообщение об ошибке в шаблон
	tmpl.Execute(w, map[string]interface{}{
		"ErrorMsg": errorMsg,
	})
}

func reg_page(w http.ResponseWriter, r *http.Request) {
	var errorMsg string

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		log.Println("Регистрация: email =", email)

		// Проверка на пустые поля
		if email == "" || password == "" {
			errorMsg = "Email и пароль обязательны"
			log.Println("Ошибка: email или пароль пусты")
		} else if password != confirmPassword {
			// Проверка совпадения паролей
			errorMsg = "Пароли не совпадают"
			log.Println("Ошибка: пароли не совпадают")
		} else {
			// Хеширование пароля
			hashedPassword, err := hashPassword(password)
			if err != nil {
				errorMsg = "Ошибка при хешировании пароля"
				log.Println("Ошибка при хешировании пароля:", err)
			} else {
				// Создание пользователя
				err = createUser(email, hashedPassword)
				if err != nil {
					errorMsg = fmt.Sprintf("Ошибка при регистрации: %v", err)
					log.Println("Ошибка при создании пользователя:", err)
				} else {
					// Если все прошло успешно, перенаправляем на страницу входа
					log.Println("Пользователь успешно создан:", email)
					http.Redirect(w, r, "/login/", http.StatusSeeOther)
					return
				}
			}
		}
	}

	// Загрузка шаблона
	tmpl, err := template.ParseFiles("templates/registration.html")
	if err != nil {
		http.Error(w, "Ошибка при загрузке шаблона", http.StatusInternalServerError)
		return
	}
	// Передаем сообщение об ошибке в шаблон
	tmpl.Execute(w, map[string]interface{}{
		"ErrorMsg": errorMsg,
	})
}

func createUser(email, hashedPassword string) error {
	// Проверка существования пользователя
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email).Scan(&exists)
	if err != nil {
		log.Println("Ошибка при проверке существования пользователя:", err)
		return err
	}
	if exists {
		log.Println("Пользователь уже существует с email:", email)
		return fmt.Errorf("пользователь с таким email уже существует")
	}

	// Попытка вставки нового пользователя
	log.Println("Попытка добавить пользователя:", email)
	result, err := db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", email, hashedPassword)
	if err != nil {
		log.Println("Ошибка при вставке пользователя:", err)
		return err
	}

	// Проверяем, сколько строк было затронуто
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println("Ошибка при получении количества затронутых строк:", err)
		return err
	}
	log.Println("Количество затронутых строк:", rowsAffected)
	return nil
}

func main_page(w http.ResponseWriter, r *http.Request) {
	tracks, err := getTracks() // Получаем треки из базы данных
	if err != nil {
		http.Error(w, "Ошибка при получении треков", http.StatusInternalServerError)
		return
	}

	// Получаем баланс пользователя
	rubBalance, usdBalance, err := getUserBalance(sessionID)

	tmpl, err := template.ParseFiles("templates/main_page.html")
	if err != nil {
		http.Error(w, "Ошибка при загрузке шаблона", http.StatusInternalServerError)
		return
	}

	// Передаем список треков и баланс в шаблон
	tmpl.Execute(w, map[string]interface{}{
		"Tracks":     tracks,
		"RubBalance": rubBalance,
		"UsdBalance": usdBalance,
	})
}

func uploadTrack(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Получаем данные из формы
		trackName := r.FormValue("track_name")
		artistNickname := r.FormValue("artist_nickname")
		genre := r.FormValue("genre")
		cloudStorageURL := r.FormValue("cloud_storage_url")
		status := "Обработка"

		var userID int = sessionID

		// Вставка данных в базу данных
		_, err := db.Exec("INSERT INTO tracks (track_name, artist_nickname, genre, cloud_storage_url, user_id, status) VALUES ($1, $2, $3, $4, $5, $6)",
			trackName, artistNickname, genre, cloudStorageURL, userID, status)
		if err != nil {
			http.Error(w, "Ошибка при добавлении трека", http.StatusInternalServerError)
			log.Println("Ошибка при вставке трека:", err)
			return
		}

		// Ответ клиенту
		fmt.Fprintf(w, "Трек успешно загружен")
	} else {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
	}
}

func getTracks() ([]Track, error) {
	var userID int = sessionID
	rows, err := db.Query("SELECT track_name, artist_nickname, genre, cloud_storage_url, status FROM tracks WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tracks []Track
	for rows.Next() {
		var track Track
		if err := rows.Scan(&track.TrackName, &track.ArtistNickname, &track.Genre, &track.CloudStorageURL, &track.Status); err != nil {
			return nil, err
		}
		tracks = append(tracks, track)
	}
	return tracks, nil
}

// Получение баланса пользователя из таблицы payouts
func getUserBalance(userID int) (float64, float64, error) {
	var rubBalance, usdBalance float64
	err := db.QueryRow("SELECT rub, usd FROM payouts WHERE user_id = $1", userID).Scan(&rubBalance, &usdBalance)
	if err != nil {
		return 0, 0, err
	}
	return rubBalance, usdBalance, nil
}

func handleRequest() {
	pageHandler()
	staticFileLoader()
	// Запуск веб-сервера
	fmt.Println("Starting server on 192.168.0.105:8080...")
	if err := http.ListenAndServe("192.168.0.105:8080", nil); err != nil {
		fmt.Println("Server error:", err)
	}
}

// Регистрация всех маршрутов
func pageHandler() {
	http.HandleFunc("/", home_page)
	http.HandleFunc("/login/", login_page)
	http.HandleFunc("/reg/", reg_page)
	http.HandleFunc("/main/", authMiddleware(main_page))
	http.HandleFunc("/upload-track/", authMiddleware(uploadTrack))
	http.HandleFunc("/logout/", logout) // Добавляем обработчик выхода
}

func staticFileLoader() {
	// Загружаем статические файлы
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
}

func main() {
	// Инициализация базы данных
	initDB()
	// Запуск веб-сервера
	handleRequest()
}

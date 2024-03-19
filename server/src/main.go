package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	gorm.Model
	Username string `gorm:"type:varchar(100);unique_index" json:"username"`
	Password string `gorm:"type:varchar(100)" json:"password"`
}

var DB *gorm.DB

func main() {
	var err error
	DB, err = ConnectDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	// GORM DB接続をクローズするための処理を追加
	sqlDB, err := DB.DB()
	if err != nil {
		log.Fatalf("Failed to get sql DB from GORM DB: %v", err)
	}
	defer sqlDB.Close()

	r := gin.Default()
	r.POST("/register", Register)
	r.POST("/login", Login)
	r.GET("/user/:id", GetUser)

	if err := r.Run(); err != nil {
		fmt.Printf("Error while running Gin server: %s\n", err)
	}
}

// func main() {
// 	db := ConnectDB()
// 	defer db.Close()

// 	r := gin.Default()
// 	r.POST("/register", Register)
// 	r.POST("/login", Login)
// 	r.GET("/user/:id", GetUser)

// 	r.Run()
// }

// func open(path string, count uint) *sql.DB {
// 	db, err := sql.Open("mysql", path)
// 	if err != nil {
// 		log.Fatal("open error:", err)
// 	}

// 	if err = db.Ping(); err != nil {
// 		time.Sleep(time.Second * 2)
// 		count--
// 		fmt.Printf("retry... count:%v\n", count)
// 		return open(path, count)
// 	}

// 	fmt.Println("db connected!!")
// 	return db
// }

// func ConnectDB() *sql.DB {
// 	var path string = fmt.Sprintf("%s:%s@tcp(db:3306)/%s?charset=utf8&parseTime=true",
// 		os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"),
// 		os.Getenv("MYSQL_DATABASE"))

// 	return open(path, 100)

// }

func ConnectDB() (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), "db", os.Getenv("MYSQL_DATABASE"))
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func Register(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while hashing password"})
		return
	}
	user.Password = string(hashedPassword)

	if err := DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while registering user"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func Login(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var foundUser User
	if err := DB.Where("username = ?", user.Username).First(&foundUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while logging in"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT Secret not found"})
		return
	}

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func GetUser(c *gin.Context) {
	username := c.Param("id")
	var user User
	if err := DB.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

package routes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"text/template"
	"time"
)

type RegisterData struct {
	AccountType string `json:"institution_type"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	ConfirmPass string `json:"confirm_pass"`
	Type        string `json:"type"`
	Years       string `json:"years"`
	License     string `json:"license"`
	Kra         string `json:"kra"`
	Phone       string `json:"phone"`
}

type Loan struct {
	Id      string `json:"id"`
	Date    string `json:"date"`
	Amount  string `json:"amount"`
	Purpose string `json:"purpose"`
	Status  string `json:"status"`
}

type User struct {
	Id              string `json:"id"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	InstitutionType string `json:"institution_type"`
	Loans           []Loan `json:"loans"`
}

const (
	businessShortCode = "174379"
	passKey           = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
)

var userProfile User

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/index.html"))
	tmpl.Execute(w, nil)
}

func AboutHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/about.html"))
	tmpl.Execute(w, nil)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// fmt.Println("ddd")
	data := RegisterData{
		// 	OrgName:     r.FormValue("orgname"),
		AccountType: r.FormValue("account-type"),
		Email:       r.FormValue("email"),
		Password:    r.FormValue("pass"),
		ConfirmPass: r.FormValue("confirm"),
		Type:        r.FormValue("type"),
		Years:       r.FormValue("years"),
		License:     r.FormValue("license"),
		Kra:         r.FormValue("kra"),
		Phone:       r.FormValue("phone"),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Error marshaling JSON", http.StatusInternalServerError)
		return
	}
	check_user, _ := http.Get(`http://localhost:3000/users?email=%s` + data.Email)

	// fmt.Println(us)
	if check_user != nil {
		println("Email already exists")
	}
	resp, err := http.Post("http://localhost:3000/users", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Error posting JSON data", http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()
	fmt.Print(data.Email, data.Password)

	tmpl := template.Must(template.ParseFiles("template/register.html"))
	tmpl.Execute(w, nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/login.html"))
	tmpl.Execute(w, nil)
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	instType := r.FormValue("inst-type")

	// Fetch users data
	url := "http://localhost:3000/users?email=" + email
	res, err := http.Get(url)
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		fmt.Println("Error fetching data:", err)
		return
	}
	defer res.Body.Close()

	// Read response body
	ResBody, err := io.ReadAll(res.Body)
	if err != nil {
		http.Error(w, "Error reading response body", http.StatusInternalServerError)
		fmt.Println("Error reading response body:", err)
		return
	}

	// Unmarshal users data
	var users []User
	if err := json.Unmarshal(ResBody, &users); err != nil {
		http.Error(w, "Error parsing JSON", http.StatusInternalServerError)
		fmt.Println("Error parsing JSON:", err)
		return
	}

	// Ensure we have at least one user
	if len(users) == 0 {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Find matching user
	isUser := false
	if users[0].Password == password {
		if instType == users[0].InstitutionType {
			isUser = true
			userProfile = users[0]
		}
	}

	if isUser {
		switch instType {
		case "business":
			BusinessHandler(w, r)
		case "microfinance":
			MfiHandler(w, r)
		default:
			http.Error(w, "Unknown institution type", http.StatusBadRequest)
		}
	} else {
		http.Error(w, "Invalid credentials or institution type", http.StatusUnauthorized)
	}
}

func BusinessHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/business_dashboard.html"))
	tmpl.Execute(w, userProfile)
}

func MfiHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/mfi_dashboard.html"))
	tmpl.Execute(w, userProfile)
}

func ErrorHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/error.html"))
	tmpl.Execute(w, nil)
}

func MfiReportHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/mfi/records.html"))
	tmpl.Execute(w, userProfile)
}

func MfiReportDownloadHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/mfi/download.html"))
	tmpl.Execute(w, userProfile)
}

// business pages routes
func BusinessActiveLoansHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/business/active_loans.html"))
	tmpl.Execute(w, userProfile)
}

func BusinessProfileHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/business/business_profile.html"))
	tmpl.Execute(w, userProfile)
}

func BusinessLoanApplicationHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/business/loan_applications.html"))
	tmpl.Execute(w, userProfile)
}

func BusinessTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/business/transactions.html"))
	tmpl.Execute(w, userProfile)
}

func LoanApplicationHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/business/loan_applications.html"))
	tmpl.Execute(w, userProfile)
}

func MsiListHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/mfi/mfis.html"))
	tmpl.Execute(w, userProfile)
}

func ApplyLoanHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("template/mfi/apply_loan.html"))
	tmpl.Execute(w, userProfile)
}

func generateTimestamp() string {
	now := time.Now()
	return now.Format("20060102150405")
}

func base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

// FetchAccessToken retrieves an access token from Safaricom's OAuth endpoint
func FetchAccessToken() (string, error) {
	url := "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
	method := "GET"
	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic eUFHd3U0UnJoQ2tSNjBWUndYQUdHdlJVampxOHd0b2dBc1ZaaUdJbGhhRlVmd3dCOjdQbkxiVnpqeXBJWGUycWNOOGRpbXpHeXFSR1VRODVteUVzZ3RoZWp6Z0hTMHVqOWpvSTFUWVZRR2UyRWFBenE=")

	res, err := client.Do(req)
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	fmt.Println(string(body)) // Read and log the response body
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}
	fmt.Printf("Response Body: %s\n", body)

	// Parse JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	// Extract access token
	accessToken, ok := response["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in response")
	}

	return accessToken, nil
}

func makePayment(accessToken, amount, phoneNumber string) error {
	timestamp := generateTimestamp()
	passwordToEncode := businessShortCode + passKey + timestamp
	base64Password := base64Encode(passwordToEncode)

	payload := map[string]interface{}{
		"BusinessShortCode": businessShortCode,
		"Password":          base64Password,
		"Timestamp":         timestamp,
		"TransactionType":   "CustomerPayBillOnline",
		"Amount":            amount,
		"PartyA":            phoneNumber,
		"PartyB":            businessShortCode,
		"PhoneNumber":       phoneNumber,
		"CallBackURL":       "https://waducbo.com/path",
		"AccountReference":  "TESAA",
		"TransactionDesc":   "LOAN",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("payment request failed: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	fmt.Println("Payment Response:", result)
	return nil
}

func MakePaymentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	amount := r.FormValue("amount")
	phoneNumber := r.FormValue("phoneNumber")

	accessToken, err := FetchAccessToken()
	if err != nil {
		http.Error(w, "Failed to fetch access token", http.StatusInternalServerError)
		fmt.Println("Error fetching access token:", err)
		return
	}

	if err := makePayment(accessToken, amount, phoneNumber); err != nil {
		http.Error(w, "Failed to make payment", http.StatusInternalServerError)
		fmt.Println("Error making payment:", err)
		return
	}

	fmt.Fprintf(w, "Payment request processed successfully")
}

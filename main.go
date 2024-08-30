package main

import (
	"fmt"
	"net/http"
	"text/template"

	"tesaa/routes"
)

func main() {
	template.ParseGlob("template/*.html")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch path {
		case "/":
			routes.HomeHandler(w, r)

		case "/about":
			routes.AboutHandler(w, r)

		case "/error":
			routes.ErrorHandler(w, r)
		case "/register":

			routes.RegisterHandler(w, r)

		case "/login":
			routes.LoginHandler(w, r)

		case "/business":
			routes.BusinessHandler(w, r)

		case "/mfi":
			routes.MfiHandler(w, r)

		case "/records":
			routes.MfiReportHandler(w, r)

		case "/download":
			routes.MfiReportDownloadHandler(w, r)
		case "/auth":
			routes.AuthHandler(w, r)

		case "/active-loans":
			routes.BusinessActiveLoansHandler(w, r)

		case "/business-profile":
			routes.BusinessProfileHandler(w, r)
		case "/loan-application":
			routes.BusinessLoanApplicationHandler(w, r)
		case "/business-transactions":
			routes.BusinessTransactionsHandler(w, r)

		case "/applyloan":
			routes.ApplyLoanHandler(w, r)
		case "/mfis":
			routes.MsiListHandler(w, r)		
		case "/make-payment":
			routes.MakePaymentHandler(w, r)
		default:
			routes.ErrorHandler(w, r)
		}
	})
	assets := http.FileServer(http.Dir("assets"))
	http.Handle("/assets/", http.StripPrefix("/assets/", assets))
	fmt.Println("server listening on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

package sign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

type RegisterResult struct {
	GUID              string        `json:"guid"`
	Active            bool          `json:"active"`
	AutomatedSigning  bool          `json:"automated_signing"`
	URL               string        `json:"url"`
	Files             []interface{} `json:"files"`
	PassedReview      bool          `json:"passed_review"`
	Pk                string        `json:"pk"`
	Processed         bool          `json:"processed"`
	Reviewed          bool          `json:"reviewed"`
	Valid             bool          `json:"valid"`
	ValidationResults interface{}   `json:"validation_results"`
	ValidationURL     string        `json:"validation_url"`
	Version           string        `json:"version"`
}

type StatusCheckResult struct {
	GUID             string `json:"guid"`
	Active           bool   `json:"active"`
	AutomatedSigning bool   `json:"automated_signing"`
	URL              string `json:"url"`
	Files            []struct {
		DownloadURL string `json:"download_url"`
		Hash        string `json:"hash"`
		Signed      bool   `json:"signed"`
	} `json:"files"`
	PassedReview      bool   `json:"passed_review"`
	Pk                string `json:"pk"`
	Processed         bool   `json:"processed"`
	Reviewed          bool   `json:"reviewed"`
	Valid             bool   `json:"valid"`
	ValidationResults struct {
		Success              bool `json:"success"`
		CompatibilitySummary struct {
			Warnings int `json:"warnings"`
			Errors   int `json:"errors"`
			Notices  int `json:"notices"`
		} `json:"compatibility_summary"`
		Notices  int           `json:"notices"`
		Warnings int           `json:"warnings"`
		Errors   int           `json:"errors"`
		Messages []interface{} `json:"messages"`
		Metadata struct {
			Listed          bool `json:"listed"`
			IdentifiedFiles struct {
			} `json:"identified_files"`
			IsWebextension       bool          `json:"is_webextension"`
			ID                   string        `json:"id"`
			ManifestVersion      int           `json:"manifestVersion"`
			Name                 string        `json:"name"`
			Type                 int           `json:"type"`
			Version              string        `json:"version"`
			TotalScannedFileSize int           `json:"totalScannedFileSize"`
			EmptyFiles           []interface{} `json:"emptyFiles"`
			JsLibs               struct {
			} `json:"jsLibs"`
			UnknownMinifiedFiles []string `json:"unknownMinifiedFiles"`
		} `json:"metadata"`
		EndingTier int `json:"ending_tier"`
	} `json:"validation_results"`
	ValidationURL string `json:"validation_url"`
	Version       string `json:"version"`
}

type Sign struct {
	xpiPath      string
	xpiFileName  string
	geckoId      string
	version      string
	jwtIssuer    string
	jwtSecret    string
	downloadPath string
}

func NewSign(xpiPath string, xpiFileName string, geckoId string, version string, jwtIssuer string, jwtSecret string, downloadPath string) *Sign {
	return &Sign{xpiPath, xpiFileName, geckoId, version, jwtIssuer, jwtSecret, downloadPath}
}

func (s *Sign) Register() error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	f, err := os.Open(s.xpiPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fw, err := w.CreateFormFile("upload", s.xpiFileName)
	if err != nil {
		return err
	}
	if _, err = io.Copy(fw, f); err != nil {
		return err
	}
	w.Close()

	url := "https://addons.mozilla.org/api/v4/addons/" + s.geckoId + "/versions/" + s.version + "/"
	req, err := http.NewRequest("PUT", url, &buf)
	if err != nil {
		return err
	}
	token := s.GetJwtToken()
	req.Header.Set("Authorization", "JWT "+token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	byteArray, _ := ioutil.ReadAll(resp.Body)
	registerResult := new(RegisterResult)
	if err := json.Unmarshal(byteArray, registerResult); err != nil {
		fmt.Println("JSON Unmarshal error:", err)
		return err
	}
	err = s.CheckStatus(registerResult)
	if err != nil {
		return err
	}
	return nil
}

func (s *Sign) CheckStatus(registerResult *RegisterResult) error {
	time.Sleep(30 * time.Second)
	req, err := http.NewRequest("GET", registerResult.URL, nil)
	if err != nil {
		return err
	}
	token := s.GetJwtToken()
	req.Header.Set("Authorization", "JWT "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	byteArray, _ := ioutil.ReadAll(resp.Body)
	statusCheckResult := new(StatusCheckResult)
	if err := json.Unmarshal(byteArray, statusCheckResult); err != nil {
		fmt.Println("JSON Unmarshal error:", err)
		return err
	}
	err = s.Download(statusCheckResult)
	if err != nil {
		return err
	}
	return nil
}

func (s *Sign) Download(statusCheckResult *StatusCheckResult) error {
	if statusCheckResult.Valid == false {
		return errors.New("invalid validation status")
	}
	req, err := http.NewRequest("GET", statusCheckResult.Files[0].DownloadURL, nil)
	if err != nil {
		return err
	}
	token := s.GetJwtToken()
	req.Header.Set("Authorization", "JWT "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(s.downloadPath + s.xpiFileName)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func (s *Sign) GetJwtToken() string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["iss"] = s.jwtIssuer
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * 5).Unix()
	tokenString, _ := token.SignedString([]byte(s.jwtSecret))
	return tokenString
}

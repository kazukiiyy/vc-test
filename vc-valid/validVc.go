package validate

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
)

// ChallengeLength は署名チャレンジとして使用するランダムなバイト数
const ChallengeLength = 32

// GenerateChallenge は認証要求に使うランダムなチャレンジ文字列を生成します
func GenerateChallenge() (string, error) {
	challengeBytes := make([]byte, ChallengeLength)
	_, err := rand.Read(challengeBytes)
	if err != nil {
		return "", fmt.Errorf("乱数生成エラー: %w", err)
	}
	// URLセーフなBase64でエンコードして文字列として返す
	return base64.URLEncoding.EncodeToString(challengeBytes), nil
}

// handleAuthRequest は認証を開始するためのAPIエンドポイントをシミュレートします
func handleAuthRequest(w http.ResponseWriter, r *http.Request) {
	// 1. 認証チャレンジを生成
	challenge, err := GenerateChallenge()
	if err != nil {
		http.Error(w, "チャレンジ生成エラー", http.StatusInternalServerError)
		log.Printf("チャレンジ生成エラー: %v", err)
		return
	}

	// 2. サーバー側でこのチャレンジと、誰に要求したか（セッションIDなど）を一時的に保存
	// 実際のシステムでは、このチャレンジをデータベースやキャッシュに保存しておき、
	// 後でウォレットから返送された署名と突き合わせるために使います。
	fmt.Printf("[サーバー] 新しい認証チャレンジを発行: %s\n", challenge)
	// Example: saveChallenge(sessionID, challenge, time.Now().Add(5*time.Minute))

	// 3. ユーザーのウォレットに送るレスポンスを作成（このチャレンジを使って署名せよ、と要求）
	response := fmt.Sprintf(`{"status": "ok", "challenge": "%s", "expires_in": 300}`, challenge)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))

	// 4. (ユーザー側) ウォレットアプリは、このレスポンスを受け取り、
	//    ユーザーの秘密鍵でこの「challenge」に署名し、次のAPIエンドポイントに返送します。
}

func main() {
	// サーバーのルーティング設定
	http.HandleFunc("/auth/challenge", handleAuthRequest)

	// 署名結果を受け取るエンドポイント（handleVerifySignatureなど）も必要

	fmt.Println("サーバーが :8080 で起動しました...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

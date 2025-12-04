package vc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"time"

	// W3C規格のVCを作成するためにJWTのクレームを定義
	"github.com/golang-jwt/jwt/v5"
)

// CredentialSubject: 証明内容（学位情報）を定義
type CredentialSubject struct {
	ID     string `json:"id"`
	Degree string `json:"degree"`
	Name   string `json:"name"`
}

// CustomClaims: VCのW3C必須フィールドとJWT標準フィールドを統合
type CustomClaims struct {
	// 'vc'フィールド内にW3Cの必須情報を格納
	VC struct {
		Context           []string          `json:"@context"`
		Type              []string          `json:"type"`
		CredentialSubject CredentialSubject `json:"credentialSubject"`
	} `json:"vc"`

	// JWT標準クレーム
	jwt.RegisteredClaims
}

func main() {
	// 1. 【準備】発行者の鍵ペアを生成 (Ed25519を使用)
	// 実際には、この秘密鍵(privKey)はKMSで安全に管理されます。
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("鍵の生成に失敗しました: %v", err)
	}

	// 2. 【VCペイロード作成】クレーム（中身）の定義
	issuerDID := "did:example:issuer:university-A"
	holderDID := "did:example:holder:student-B"

	claims := CustomClaims{
		VC: struct {
			Context           []string          `json:"@context"`
			Type              []string          `json:"type"`
			CredentialSubject CredentialSubject `json:"credentialSubject"`
		}{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1",
			},
			Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
			CredentialSubject: CredentialSubject{
				ID:     holderDID,
				Degree: "Bachelor of Science",
				Name:   "Ken Tanaka",
			},
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuerDID, // 発行者ID (Issuer)
			Subject:   holderDID, // 保有者ID (Subject)
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 365)), // 1年後に期限切れ
			ID:        "vc-id-12345",                                            // VCを一意に識別するID (JTI)
		},
	}

	// 3. 【署名】トークンオブジェクトを作成し、秘密鍵で署名
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	// EdDSA (Ed25519) アルゴリズムで秘密鍵を使って署名
	signedVC, err := token.SignedString(privKey)
	if err != nil {
		log.Fatalf("VCの署名に失敗しました: %v", err)
	}

	// 4. 【結果出力】
	fmt.Println("--- 発行された Verifiable Credential (JWT) ---")
	fmt.Println(signedVC)
	fmt.Println("\n--- 検証に必要な情報 ---")
	fmt.Printf("発行者DID: %s\n", issuerDID)
	fmt.Printf("公開鍵 (Hex): %x\n", pubKey)
}

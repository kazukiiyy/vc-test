package kmsc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	// AWS SDK v2
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// SignVCPayloadWithKMS は、AWS KMSを使用してVCペイロードに署名を行います。
// 秘密鍵はサーバーに出ることはなく、KMS内で署名が実行されます。
func SignVCPayloadWithKMS(keyARN string, vcPayload []byte) ([]byte, error) {
	// 1. AWS設定とKMSクライアントの初期化
	// 環境変数、IAMロールなどから認証情報をロード
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("AWS設定のロードに失敗しました: %w", err)
	}
	kmsClient := kms.NewFromConfig(cfg)

	// 2. 署名対象データのハッシュ計算
	// KMSは、通常、署名対象のデータそのものではなく、そのデータのハッシュ値を受け取ります。
	hash := sha256.Sum256(vcPayload)

	// 3. KMS署名リクエストの作成
	input := &kms.SignInput{
		KeyId:            &keyARN,
		Message:          hash[:],                               // ハッシュ値のバイト配列を渡す
		MessageType:      types.MessageTypeDigest,               // メッセージはハッシュ（ダイジェスト）であると指定
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256, // 使用するアルゴリズムを指定
	}

	// 4. KMS APIの実行（秘密鍵による署名処理を依頼）
	fmt.Printf("[KMS Request] KMS Key ARN (%s) に対し署名要求を送信中...\n", keyARN)
	result, err := kmsClient.Sign(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("KMS Sign API呼び出しエラー: %w", err)
	}

	// 5. 署名結果の取得
	if result.Signature == nil {
		return nil, fmt.Errorf("KMSから署名結果が返されませんでした")
	}

	fmt.Println("[KMS Response] 署名データを安全に取得しました。")
	// 取得した署名データは、VCの 'proof' フィールドに組み込まれます。
	return result.Signature, nil
}

func main() {
	// -----------------------------------------------------------------
	// 実際の利用例: VC発行サーバーのバックエンドロジック
	// -----------------------------------------------------------------

	// 🚨 テスト用のダミーのKey ARNとペイロード (実際のものに置き換えてください)
	const issuerKeyARN = "arn:aws:kms:ap-northeast-1:123456789012:key/your-kms-key-id"
	vcPayload := []byte(`{"issuer": "did:web:mycorp.com", "credentialSubject": {"id": "did:key:abc"}, "claim": "Example VC"}`)

	fmt.Printf("署名対象のVCペイロード: %s\n", string(vcPayload))

	// KMSを使用して署名を実行
	signatureBytes, err := SignVCPayloadWithKMS(issuerKeyARN, vcPayload)
	if err != nil {
		log.Fatalf("VC署名処理が失敗しました: %v", err)
	}

	// 署名結果の表示
	fmt.Println("--------------------------------------------------")
	fmt.Printf("✅ VC署名が完了しました。\n")
	fmt.Printf("署名データの長さ: %d バイト\n", len(signatureBytes))
	// 署名結果をVCのproofフィールドに組み込む処理が続く...
}

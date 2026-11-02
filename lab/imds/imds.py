from flask import Flask, request, jsonify

app = Flask(__name__)

TOKEN = "lab-imds-token-abc123"


@app.put("/latest/api/token")
def issue_token():
    if not request.headers.get("X-aws-ec2-metadata-token-ttl-seconds"):
        return "missing ttl header", 400
    return TOKEN, 200


@app.get("/latest/meta-data/")
def root():
    return "iam/"


@app.get("/latest/meta-data/iam/security-credentials/")
def roles():
    return "lab-role"


@app.get("/latest/meta-data/iam/security-credentials/lab-role")
def creds():
    if request.headers.get("X-aws-ec2-metadata-token") != TOKEN:
        return "unauthorized", 401
    return jsonify(
        Code="Success",
        Type="AWS-HMAC",
        AccessKeyId="AKIAFAKELAB00000001",
        SecretAccessKey="FakeSecretKeyForLabOnly0000000000000000000",
        Token="FakeSessionTokenForLabOnly",
        Expiration="2030-01-01T00:00:00Z",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)

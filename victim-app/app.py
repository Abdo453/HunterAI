from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"Result for: {q}"

@app.route("/")
def index():
    return "Victim app is running. Try /search?q=test"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)

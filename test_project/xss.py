from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<p>You searched for: {q}</p>"

# /search?q=<script>alert(1)</script>

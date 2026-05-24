from flask import Blueprint, render_template, request, jsonify, current_app
from app.analyzers.entropy import analyze_entropy
from app.analyzers.patterns import detect_all_patterns
from app.analyzers.charset import analyze_charset
from app.analyzers.strength_score import compute_score
from app.analyzers.breach import check_breach
from app.models.report import PasswordReport, build_advice

analysis_bp = Blueprint("analysis", __name__)

@analysis_bp.route("/")
def index():
    return render_template("index.html")

@analysis_bp.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password is required."}), 400

    max_len = current_app.config["MAX_PASSWORD_LENGTH"]

    if len(password) > max_len:
        return jsonify({"error": f"Password must be under {max_len} characters."}), 400

    entropy_result = analyze_entropy(password)
    charset_result = analyze_charset(password)
    patterns = detect_all_patterns(password)

    score, label = compute_score(
        entropy_result,
        charset_result,
        patterns
    )

    breach_result = check_breach(
        password,
        timeout=current_app.config["HIBP_TIMEOUT"],
        user_agent=current_app.config["HIBP_USER_AGENT"],
    )

    advice = build_advice(
        entropy_result,
        charset_result,
        patterns,
        breach_result
    )

    report = PasswordReport(
        score=score,
        label=label,
        entropy=entropy_result.bits,
        charset_size=entropy_result.charset_size,
        crack_time=entropy_result.crack_time,
        charset_composition=charset_result.composition,
        patterns=[p._asdict() for p in patterns],
        breached=breach_result.breached,
        breach_count=breach_result.count,
        advice=advice,
        error=breach_result.error,
    )

    return jsonify(report.to_dict())
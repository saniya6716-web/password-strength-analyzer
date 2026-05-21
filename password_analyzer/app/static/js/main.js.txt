const analyzeBtn = document.getElementById("analyze-btn");

analyzeBtn.addEventListener("click", runAnalysis);

async function runAnalysis() {

    const password = document.getElementById("password-input").value;

    if (!password) {
        alert("Enter password");
        return;
    }

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                password: password
            })
        });

        const data = await response.json();

        document.getElementById("score-label").textContent = data.label;

        document.getElementById("score-number").textContent = data.score;

        document.getElementById("entropy-value").textContent =
            data.entropy + " bits";

        document.getElementById("crack-value").textContent =
            data.crack_time;

        if (data.breached) {
            document.getElementById("breach-value").textContent =
                "Breached";
        } else {
            document.getElementById("breach-value").textContent =
                "Safe";
        }

    } catch (error) {

        alert("Error connecting to server");

    }
}
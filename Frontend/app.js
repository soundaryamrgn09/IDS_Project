// =======================
// REGISTER
// =======================
function registerUser() {

    const u = document.getElementById("user").value.trim();
    const p = document.getElementById("pass").value.trim();

    if (!u || !p) {
        alert("Fill all fields");
        return;
    }

    fetch("http://127.0.0.1:5001/register", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: u,
            password: p
        })
    })
    .then(res => res.json())
    .then(data => {
        if(data.status === "success"){
            alert("Registered Successfully");
            window.location.href = "login.html";
        } else {
            alert(data.message || "User already exists");
        }
    })
    .catch(() => {
        alert("Server error");
    });
}

// =======================
// LOGIN
// =======================
function loginUser(){

    const u = document.getElementById("user").value.trim();
    const p = document.getElementById("pass").value.trim();

    if (!u || !p) {
        alert("Fill all fields");
        return;
    }

    fetch("http://127.0.0.1:5001/login",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
            username:u,
            password:p
        })
    })
    .then(res=>res.json())
    .then(data=>{
        if(data.status==="success"){
            sessionStorage.setItem("logged","yes");
            window.location.href="home.html";
        } else {
            alert(data.message || "Invalid login");
        }
    })
    .catch(() => {
        alert("Server error");
    });
}

// =======================
// AUTH CHECK
// =======================
function checkAuth() {
    if (sessionStorage.getItem("logged") !== "yes") {
        window.location.href = "login.html";
    }
}

// =======================
// LOGOUT
// =======================
function logout() {
    sessionStorage.clear();
    window.location.href = "login.html";
}

// =======================
// SHAP GRAPH INIT
// =======================
let shapChart = null;

function initShapChart() {

    const ctx = document.getElementById("shapChart");
    if (!ctx) return;

    shapChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: [
                "src_bytes",
                "count",
                "srv_serror_rate",
                "dst_host_srv_count",
                "logged_in"
            ],
            datasets: [{
                label: "SHAP Impact",
                data: [],
                backgroundColor: "rgba(99,102,241,0.6)",
                borderColor: "#6366f1",
                borderWidth: 2
            }]
        },
        options: {
            animation: { duration: 800 },
            plugins: {
                legend: {
                    labels: { color: "#475569" }
                }
            }
        }
    });
}

// =======================
// LIVE PREDICTION
// =======================
function initLivePrediction() {

    initShapChart();

    const socket = io("http://127.0.0.1:5001", {
    transports: ["websocket", "polling"]
});
    
    socket.on("connect", () => {
        console.log("Socket connected");
    });

    const feed = document.getElementById("feed");
    const scoreEl = document.getElementById("anomScore");
    const riskLevelEl = document.getElementById("riskLevel");
    const isoResultEl = document.getElementById("isoResult");

    // MAP
    window.liveMap = L.map("map").setView([20, 0], 2);

    L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
    ).addTo(liveMap);

    socket.on("new_detection", (data) => {

        const isAttack = data.status.includes("Attack");

        // FEED
        if (feed) {
            const div = document.createElement("div");
            div.className = isAttack ? "attack" : "normal";
            div.innerHTML = `[${data.timestamp}] ${data.status}`;
            feed.prepend(div);
        }

        // MAP MARKER
        const lat = (Math.random() * 120) - 60;
        const lon = (Math.random() * 360) - 180;

        const marker = L.circleMarker([lat, lon], {
            radius: isAttack ? 10 : 6,
            color: isAttack ? "#ef4444" : "#22c55e",
            fillColor: isAttack ? "#ef4444" : "#22c55e",
            fillOpacity: 0.8
        }).addTo(liveMap);

        setTimeout(() => {
            liveMap.removeLayer(marker);
        }, 6000);

        // ZERO DAY
        const score = data.anomaly_score;

        if (scoreEl)
            scoreEl.innerText = score.toFixed(3);

        if (data.zero_day) {
            riskLevelEl.innerText = "Zero-Day Attack";
            riskLevelEl.style.color = "#ef4444";
            isoResultEl.innerText = "Anomaly Detected";
        } else {
            riskLevelEl.innerText = "Normal";
            riskLevelEl.style.color = "#22c55e";
            isoResultEl.innerText = "No Anomaly";
        }

        // SHAP
        if (shapChart && data.shap) {
            shapChart.data.datasets[0].data = data.shap;
            shapChart.update();
        }

    });
}

// =======================
// METRIC ANIMATION
// =======================
function animateValue(id, value) {
    let el = document.getElementById(id);
    let start = 0;
    let end = parseFloat(value);
    let step = end === 0 ? 1 : end / 50;

    let interval = setInterval(() => {
        start += step;

        if (start >= end) {
            el.innerText = end.toFixed(2) + "%";
            clearInterval(interval);
        } else {
            el.innerText = start.toFixed(2) + "%";
        }
    }, 20);
}

// =======================
// ANALYSIS PAGE
// =======================
function loadAnalysisCharts() {

    const socket = io("http://127.0.0.1:5001");

    socket.emit("request_metrics");

    socket.on("real_metrics", m => {

        if (m.error) {
            alert("Test dataset missing");
            return;
        }

        animateValue("acc", m.accuracy * 100);
        animateValue("prec", m.precision * 100);
        animateValue("rec", m.recall * 100);
        animateValue("f1", m.f1 * 100);

        const options = {
    animation: { duration: 1000 },
    plugins: {
        legend: {
            labels: { color: "#e2e8f0" }
        }
    },
    scales: {
        x: { ticks: { color: "#94a3b8" } },
        y: { ticks: { color: "#94a3b8" } }
    }
};
        new Chart(document.getElementById("cm"), {
            type: "bar",
            data: {
                labels: ["TN", "FP", "FN", "TP"],
                datasets: [{
                    data: [m.cm.tn, m.cm.fp, m.cm.fn, m.cm.tp],
                    backgroundColor: "rgba(0,245,255,0.6)",
                    borderColor: "#00f5ff",
                    borderWidth: 2
                }]
            },
            options
        });

        new Chart(document.getElementById("roc"), {
            type: "line",
            data: {
                labels: m.roc.fpr,
                datasets: [{
                    label: "ROC Curve",
                    data: m.roc.tpr,
                    borderColor: "#22c55e",
                    tension: 0.4
                }]
            },
            options
        });

        new Chart(document.getElementById("pr"), {
            type: "line",
            data: {
                labels: m.pr_curve.recall,
                datasets: [{
                    label: "Precision-Recall",
                    data: m.pr_curve.precision,
                    borderColor: "#00f5ff",
                    tension: 0.4
                }]
            },
            options
        });

        new Chart(document.getElementById("feat"), {
            type: "bar",
            data: {
                labels: [
                    "duration","protocol_type","service","flag",
                    "src_bytes","dst_bytes","count",
                    "srv_count","serror_rate","srv_serror_rate"
                ],
                datasets: [{
                    label: "Feature Importance",
                    data: m.feature_importance,
                    backgroundColor: "rgba(99,102,241,0.6)",
                    borderColor: "#6366f1",
                    borderWidth: 2
                }]
            },
            options
        });

    });
}

// =======================
// CARD HOVER EFFECT
// =======================
document.addEventListener("DOMContentLoaded", () => {

    const cards = document.querySelectorAll(".card");

    if (cards.length > 0) {

        cards.forEach(card => {

            card.addEventListener("mousemove", e => {

                card.style.transition = "transform 0.1s ease";

                let x = e.offsetX;
                let y = e.offsetY;

                let centerX = card.offsetWidth / 2;
                let centerY = card.offsetHeight / 2;

                let rotateX = -(y - centerY) / 20;
                let rotateY = (x - centerX) / 20;

                card.style.transform =
                    `rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale(1.02)`;
            });

            card.addEventListener("mouseleave", () => {
                card.style.transform = "rotateX(0) rotateY(0) scale(1)";
            });

        });

    }

});

// =======================
// LOADER
// =======================
window.addEventListener("load", () => {
    const loader = document.getElementById("loader");
    if (loader) loader.style.display = "none";
});
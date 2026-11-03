/* =====================================================
   SMART QR CODE FRAUD DETECTION
   JavaScript Prototype
   ===================================================== */


/* ================= TRUSTED PROFILES ================= */

let profiles = JSON.parse(
    localStorage.getItem("trustedProfiles")
) || [

    {
        ssid: "Campus_Official",
        security: "WPA2"
    },

    {
        ssid: "Easwari_Staff_WiFi",
        security: "WPA3"
    },

    {
        ssid: "Hostel_Broadband",
        security: "WPA2"
    },

    {
        ssid: "Research_Lab_5G",
        security: "WPA3"
    }

];


/* ================= CURRENT DATA ================= */

let currentConfig = null;


/* ================= PAGE NAVIGATION ================= */

function showPage(pageName) {

    document.querySelectorAll(".page").forEach(page => {
        page.classList.remove("active");
    });

    document.getElementById(pageName).classList.add("active");
}


/* ================= WIFI QR PARSER ================= */

function parseWiFiQR(data) {

    if (!data) {
        throw new Error("Invalid Wi-Fi QR format.");
    }

    // Remove spaces and invisible characters
    data = data.trim().replace(/^\uFEFF/, "");

    // Accept WIFI: or wifi:
    if (!data.toUpperCase().startsWith("WIFI:")) {
        throw new Error(
            "Invalid Wi-Fi QR format. Please upload a Wi-Fi QR code."
        );
    }

    // Remove WIFI: prefix
    let content = data.substring(5);

    let fields = {};

    // Read the Wi-Fi QR fields
    let parts = content.split(";");

    parts.forEach(part => {

        if (!part) return;

        let separator = part.indexOf(":");

        if (separator === -1) return;

        let key = part.substring(0, separator).toUpperCase();
        let value = part.substring(separator + 1);

        fields[key] = value;
    });

    // SSID is required
    if (!fields["S"]) {
        throw new Error(
            "Invalid Wi-Fi QR format. Network name was not found."
        );
    }

    return {
        ssid: fields["S"],
        security: fields["T"] || "nopass",
        password: fields["P"] || "",
        hidden: fields["H"] || "false"
    };
}

/* ================= SHANNON ENTROPY ================= */

function calculateEntropy(password) {

    if (!password) {
        return 0;
    }

    let frequencies = {};

    for (let char of password) {

        frequencies[char] =
            (frequencies[char] || 0) + 1;

    }

    let entropy = 0;

    let length = password.length;

    for (let char in frequencies) {

        let probability =
            frequencies[char] / length;

        entropy -=
            probability *
            Math.log2(probability);

    }

    return entropy;
}


/* ================= RISK ANALYSIS ================= */

function analyzeSecurity(config) {

    let score = 0;

    let findings = [];

    let recommendations = [];

    let security =
        config.security.toLowerCase();


    /* ---------- PROTOCOL RISK ---------- */

    if (security === "nopass") {

        score += 50;

        findings.push(
            "Open Wi-Fi network detected. No encryption is configured."
        );

        recommendations.push(
            "Avoid open networks and use a secured Wi-Fi connection."
        );

    }

    else if (security === "wep") {

        score += 55;

        findings.push(
            "WEP encryption detected. WEP is obsolete and vulnerable."
        );

        recommendations.push(
            "Use WPA2 or WPA3 instead of WEP."
        );

    }

    else if (security === "wpa") {

        score += 35;

        findings.push(
            "Legacy WPA security detected."
        );

        recommendations.push(
            "Upgrade the network to WPA2 or WPA3."
        );

    }

    else if (security === "wpa2") {

        score += 10;

        findings.push(
            "WPA2 security detected."
        );

        recommendations.push(
            "WPA2 is acceptable, but WPA3 is preferred where available."
        );

    }

    else if (security === "wpa3") {

        score += 0;

        findings.push(
            "WPA3 security detected."
        );

        recommendations.push(
            "Continue using WPA3 and keep router firmware updated."
        );

    }


    /* ---------- PASSWORD ANALYSIS ---------- */

    let password = config.password;

    let entropy = calculateEntropy(password);

    if (
        password.length < 8 ||
        entropy < 2.0
    ) {

        score += 25;

        findings.push(
            "Weak Wi-Fi password detected."
        );

        recommendations.push(
            "Use a strong password with sufficient length and complexity."
        );

    }

    else if (entropy < 3.0) {

        score += 10;

        findings.push(
            "Password entropy is relatively low."
        );

        recommendations.push(
            "Consider using a stronger and more random password."
        );

    }


    /* ---------- TRUSTED PROFILE CHECK ---------- */

    let trustedProfile =
        profiles.find(
            profile =>
                profile.ssid.toLowerCase() ===
                config.ssid.toLowerCase()
        );


    let evilTwin = false;


    if (trustedProfile) {

        if (
            trustedProfile.security.toLowerCase() !==
            config.security.toLowerCase()
        ) {

            score += 45;

            evilTwin = true;

            findings.push(
                "Security type does not match the trusted network profile. Possible Evil Twin or rogue access point."
            );

            recommendations.push(
                "Do not connect until the network identity and security configuration are verified."
            );

        }

    }


    /* ---------- LIMIT SCORE ---------- */

    score = Math.min(score, 100);


    /* ---------- RISK LEVEL ---------- */

    let level;

    if (score >= 90) {

        level = "CRITICAL";

    }

    else if (score >= 70) {

        level = "HIGH";

    }

    else if (score >= 40) {

        level = "MODERATE";

    }

    else if (score >= 20) {

        level = "LOW";

    }

    else {

        level = "SAFE";

    }


    return {

        score,
        level,
        findings,
        recommendations,
        evilTwin

    };

}


/* ================= AUDIT QR ================= */

function auditQR() {

    let input =
        document.getElementById("qrInput").value;

    try {

        currentConfig =
            parseWiFiQR(input);

    }

    catch (error) {

        alert(error.message);

        return;

    }


    /* Display parsed fields */

    document.getElementById("network").textContent =
        currentConfig.ssid;

    document.getElementById("security").textContent =
        currentConfig.security;

    document.getElementById("password").textContent =
        currentConfig.password || "(empty)";

    document.getElementById("hidden").textContent =
        currentConfig.hidden;


    /* Analyze */

    let result =
        analyzeSecurity(currentConfig);


    /* Update report */

    document.getElementById("riskScore").textContent =
        result.score;

    document.getElementById("riskLevel").textContent =
        result.level;

    document.getElementById("reportSSID").textContent =
        currentConfig.ssid;

    document.getElementById("reportSecurity").textContent =
        currentConfig.security;

    document.getElementById("evilTwin").textContent =
        result.evilTwin ? "Possible" : "No mismatch";


    /* Findings */

    let findingsElement =
        document.getElementById("findings");

    findingsElement.innerHTML = "";

    result.findings.forEach(finding => {

        let li =
            document.createElement("li");

        li.textContent = finding;

        findingsElement.appendChild(li);

    });


    /* Recommendations */

    let recommendationsElement =
        document.getElementById("recommendations");

    recommendationsElement.innerHTML = "";

    result.recommendations.forEach(recommendation => {

        let li =
            document.createElement("li");

        li.textContent = recommendation;

        recommendationsElement.appendChild(li);

    });


    /* Save audit */

    saveAudit(
        currentConfig.ssid,
        result.score,
        result.level
    );


    /* Refresh history */

    displayHistory();


    /* Open report */

    showPage("report");

}


/* ================= TEST CASES ================= */

function loadTest(type) {

    let qr = "";


    if (type === "guest") {

        qr =
            "WIFI:S:Guest_WiFi;T:nopass;P:;H:false;;";

    }

    else if (type === "evil") {

        qr =
            "WIFI:S:Campus_Official;T:nopass;P:;H:false;;";

    }

    else if (type === "lookalike") {

        qr =
            "WIFI:S:Campus_Officia1;T:WPA2;P:Campus123;H:false;;";

    }

    else if (type === "wep") {

        qr =
            "WIFI:S:Old_Lab;T:WEP;P:12345678;H:false;;";

    }

    else if (type === "weak") {

        qr =
            "WIFI:S:WeakNetwork;T:WPA2;P:1234;H:false;;";

    }

    else if (type === "safe") {

        qr =
            "WIFI:S:Research_Lab_5G;T:WPA3;P:StrongPassword123;H:false;;";

    }


    document.getElementById("qrInput").value = qr;

    auditQR();

}


/* ================= PROFILES ================= */

function displayProfiles() {

    let table =
        document.getElementById("profileTable");

    table.innerHTML = "";


    profiles.forEach((profile, index) => {

        let row =
            document.createElement("tr");

        row.innerHTML = `

            <td>${profile.ssid}</td>

            <td>${profile.security}</td>

            <td>
                <button
                    class="delete-btn"
                    onclick="deleteProfile(${index})">
                    Delete
                </button>
            </td>

        `;

        table.appendChild(row);

    });

}


/* ================= ADD PROFILE ================= */

function addProfile() {

    let ssid =
        document.getElementById("newSSID").value.trim();

    let security =
        document.getElementById("newSecurity").value;


    if (!ssid) {

        alert("Please enter a network name.");

        return;

    }


    profiles.push({

        ssid: ssid,
        security: security

    });


    localStorage.setItem(
        "trustedProfiles",
        JSON.stringify(profiles)
    );


    document.getElementById("newSSID").value = "";


    displayProfiles();

    alert("Trusted network registered successfully.");

}


/* ================= DELETE PROFILE ================= */

function deleteProfile(index) {

    profiles.splice(index, 1);

    localStorage.setItem(
        "trustedProfiles",
        JSON.stringify(profiles)
    );

    displayProfiles();

}


/* ================= HISTORY ================= */

function saveAudit(
    network,
    score,
    level
) {

    let history =
        JSON.parse(
            localStorage.getItem("auditHistory")
        ) || [];


    history.unshift({

        time:
            new Date().toLocaleString(),

        network,
        score,
        level

    });


    localStorage.setItem(
        "auditHistory",
        JSON.stringify(history)
    );

}


/* ================= DISPLAY HISTORY ================= */

function displayHistory() {

    let history =
        JSON.parse(
            localStorage.getItem("auditHistory")
        ) || [];


    let table =
        document.getElementById("historyTable");

    table.innerHTML = "";


    history.forEach(item => {

        let row =
            document.createElement("tr");


        row.innerHTML = `

            <td>${item.time}</td>

            <td>${item.network}</td>

            <td>${item.score}/100</td>

            <td>${item.level}</td>

        `;


        table.appendChild(row);

    });

}


/* ================= CLEAR HISTORY ================= */

function clearHistory() {

    localStorage.removeItem("auditHistory");

    displayHistory();

}


/* ================= QR PHOTO ================= */

/* ================= QR PHOTO UPLOAD ================= */

/* ================= QR PHOTO UPLOAD ================= */

function uploadQR(event) {

    const file = event.target.files[0];

    if (!file) {
        return;
    }

    // Check whether QR scanning library is available
    if (typeof Html5Qrcode === "undefined") {
        alert("QR scanner library could not be loaded.");
        return;
    }

    // Create a temporary hidden element for QR decoding
    const reader = document.createElement("div");

    reader.id = "temporaryQRReader";

    reader.style.position = "fixed";
    reader.style.left = "-10000px";
    reader.style.top = "-10000px";
    reader.style.width = "1px";
    reader.style.height = "1px";

    document.body.appendChild(reader);

    // Create QR image scanner
    const scanner = new Html5Qrcode("temporaryQRReader");

    // Read the uploaded QR image
    scanner.scanFile(file, true)

        .then(function(decodedText) {

            console.log("QR payload extracted:", decodedText);

            /*
             * IMPORTANT:
             * Put the extracted payload into
             * the existing Wi-Fi QR Payload box.
             */

            const qrInput =
                document.getElementById("qrInput");

            qrInput.value = decodedText;


            /*
             * Check whether the QR actually
             * contains a Wi-Fi payload.
             */

            if (
                !decodedText
                    .trim()
                    .toUpperCase()
                    .startsWith("WIFI:")
            ) {

                alert(
                    "QR detected, but it is not a Wi-Fi QR code."
                );

                scanner.clear().catch(function() {});
                reader.remove();

                return;
            }


            /*
             * QR successfully extracted.
             * Do NOT audit automatically.
             *
             * The user will press
             * "Audit this QR".
             */

            alert(
                "Wi-Fi QR payload extracted successfully!"
            );


            scanner.clear().catch(function() {});
            reader.remove();

        })

        .catch(function(error) {

            console.error(
                "QR extraction failed:",
                error
            );

            scanner.clear().catch(function() {});
            reader.remove();

            alert(
                "Could not read the QR image.\n\n" +
                "Please upload a clear QR code image."
            );

        });


    // Allow the same image to be selected again
    event.target.value = "";
}


/* ================= START SCANNER ================= */

function startScanner() {

    const scannerSection =
        document.getElementById("scannerSection");

    scannerSection.style.display = "block";

    if (qrScanner !== null) {
        return;
    }

    qrScanner = new Html5Qrcode("reader");

    qrScanner.start(
        { facingMode: "environment" },

        {
            fps: 10,
            qrbox: {
                width: 250,
                height: 250
            }
        },

        function(decodedText) {

            console.log("QR detected:", decodedText);

            /* Put scanned text into QR input */

            document.getElementById("qrInput").value =
                decodedText;

            /* Stop camera */

            stopScanner();

            /* Automatically audit QR */

            auditQR();

        },

        function(errorMessage) {

            /*
             * The scanner continuously tries to read
             * the QR code, so normal failed frames
             * are ignored.
             */

        }

    ).catch(function(error) {

        console.error("Camera error:", error);

        alert(
            "Could not access the camera. Please allow camera permission and try again."
        );

        stopScanner();

    });

}


/* ================= STOP SCANNER ================= */

function stopScanner() {

    if (qrScanner !== null) {

        qrScanner.stop()
            .then(function() {

                qrScanner.clear();

                qrScanner = null;

            })
            .catch(function(error) {

                console.log(
                    "Scanner stop error:",
                    error
                );

                qrScanner = null;

            });

    }

    document.getElementById(
        "scannerSection"
    ).style.display = "none";

}

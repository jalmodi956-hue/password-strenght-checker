document.addEventListener("DOMContentLoaded", function () {
    const passwordInput = document.getElementById("password");
    const toggleBtn = document.getElementById("togglePassword");
    const copyBtn = document.getElementById("copyPassword");

    const strengthBar = document.getElementById("strengthBar");
    const strengthText = document.getElementById("strengthText");
    const scoreText = document.getElementById("scoreText");

    // Optional live preview fields (if present in HTML)
    const liveEntropy = document.getElementById("liveEntropy");
    const liveCrackTime = document.getElementById("liveCrackTime");
    const liveFeedback = document.getElementById("liveFeedback");

    const COMMON_WEAK_PASSWORDS = [
        "123456", "123456789", "password", "admin", "qwerty",
        "abc123", "letmein", "welcome", "iloveyou", "000000",
        "password123", "admin123", "india123", "test123"
    ];

    // -------------------------
    // Helper Functions
    // -------------------------
    function hasRepeatedChars(password) {
        return /(.)\1{2,}/.test(password);
    }

    function hasSequence(password) {
        const passwordLower = password.toLowerCase();
        const sequences = [
            "0123456789",
            "1234567890",
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ];

        for (const seq of sequences) {
            for (let i = 0; i < seq.length - 2; i++) {
                const part = seq.substring(i, i + 3);
                if (passwordLower.includes(part)) {
                    return true;
                }
            }
        }
        return false;
    }

    function hasKeyboardPattern(password) {
        const passwordLower = password.toLowerCase();
        const patterns = ["qwerty", "asdf", "zxcv", "qaz", "wsx", "edc"];
        return patterns.some(pattern => passwordLower.includes(pattern));
    }

    function calculateCharsetSize(password) {
        let charset = 0;
        if (/[a-z]/.test(password)) charset += 26;
        if (/[A-Z]/.test(password)) charset += 26;
        if (/[0-9]/.test(password)) charset += 10;
        if (/[^A-Za-z0-9]/.test(password)) charset += 32;
        return charset;
    }

    function calculateEntropy(password) {
        const charset = calculateCharsetSize(password);
        if (!password || charset === 0) return 0;
        return (password.length * Math.log2(charset)).toFixed(2);
    }

    function estimateCrackTime(entropy) {
        entropy = parseFloat(entropy);
        if (entropy <= 0) return "Instantly";

        const guesses = Math.pow(2, entropy);
        const guessesPerSecond = 1000000000; // demo estimate
        const seconds = guesses / guessesPerSecond;

        if (seconds < 1) return "Less than 1 second";
        if (seconds < 60) return `${Math.floor(seconds)} seconds`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
        if (seconds < 2592000) return `${Math.floor(seconds / 86400)} days`;
        if (seconds < 31536000) return `${Math.floor(seconds / 2592000)} months`;
        if (seconds < 3153600000) return `${Math.floor(seconds / 31536000)} years`;
        return "Many years";
    }

    // -------------------------
    // Password Strength Engine
    // -------------------------
    function checkStrength(password) {
        let score = 0;
        let feedback = [];

        if (!password) {
            return {
                score: 0,
                strength: "Weak",
                color: "#ef4444",
                feedback: ["Please enter a password"],
                entropy: 0,
                crackTime: "Instantly"
            };
        }

        // Length
        if (password.length >= 16) score += 30;
        else if (password.length >= 12) score += 25;
        else if (password.length >= 8) score += 18;
        else feedback.push("Use at least 8 characters");

        // Uppercase
        if (/[A-Z]/.test(password)) score += 12;
        else feedback.push("Add at least one uppercase letter");

        // Lowercase
        if (/[a-z]/.test(password)) score += 12;
        else feedback.push("Add at least one lowercase letter");

        // Number
        if (/[0-9]/.test(password)) score += 12;
        else feedback.push("Add at least one number");

        // Special character
        if (/[!@#$%^&*(),.?":{}|<>_\-+=/\\[\];'`~]/.test(password)) score += 16;
        else feedback.push("Add at least one special character");

        // Bonus
        const specialCount = (password.match(/[^A-Za-z0-9]/g) || []).length;
        if (specialCount >= 2) score += 6;
        if (new Set(password).size >= 8) score += 5;

        // Penalties
        if (COMMON_WEAK_PASSWORDS.includes(password.toLowerCase())) {
            score -= 35;
            feedback.push("This is a very common password. Avoid common passwords.");
        }

        if (hasRepeatedChars(password)) {
            score -= 10;
            feedback.push("Avoid repeated characters like aaa or 111");
        }

        if (hasSequence(password)) {
            score -= 10;
            feedback.push("Avoid easy sequences like 123, abc, qwe");
        }

        if (hasKeyboardPattern(password)) {
            score -= 8;
            feedback.push("Avoid keyboard patterns like qwerty or asdf");
        }

        // Clamp score
        score = Math.max(0, Math.min(score, 100));

        let strength = "Weak";
        let color = "#ef4444";

        if (score <= 40) {
            strength = "Weak";
            color = "#ef4444";
        } else if (score <= 75) {
            strength = "Medium";
            color = "#f59e0b";
        } else {
            strength = "Strong";
            color = "#22c55e";
        }

        const entropy = calculateEntropy(password);
        const crackTime = estimateCrackTime(entropy);

        if (entropy < 40) {
            feedback.push("Entropy is low. Use a longer and less predictable password.");
        } else if (entropy >= 60 && score >= 75) {
            feedback.push("Good entropy level. This password is relatively strong.");
        }

        return {
            score,
            strength,
            color,
            feedback,
            entropy,
            crackTime
        };
    }

    // -------------------------
    // Live UI Update
    // -------------------------
    function renderLiveFeedback(feedback, strength) {
        if (!liveFeedback) return;

        if (!feedback || feedback.length === 0) {
            liveFeedback.innerHTML = `<li>Excellent. Your password currently looks strong.</li>`;
            return;
        }

        // Keep max 4 live feedback lines for cleaner UI
        const limited = feedback.slice(0, 4);
        liveFeedback.innerHTML = limited.map(item => `<li>${item}</li>`).join("");
    }

    function updateStrengthUI() {
        if (!passwordInput || !strengthBar || !strengthText || !scoreText) return;

        const password = passwordInput.value;
        const result = checkStrength(password);

        strengthBar.style.width = result.score + "%";
        strengthBar.style.background = result.color;

        strengthText.textContent = result.strength;
        strengthText.style.color = result.color;

        scoreText.textContent = result.score + "/100";

        if (liveEntropy) {
            liveEntropy.textContent = result.entropy;
        }

        if (liveCrackTime) {
            liveCrackTime.textContent = result.crackTime;
        }

        renderLiveFeedback(result.feedback, result.strength);
    }

    if (passwordInput) {
        passwordInput.addEventListener("input", updateStrengthUI);
    }

    // -------------------------
    // Show / Hide Password
    // -------------------------
    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", function () {
            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                toggleBtn.textContent = "Hide";
            } else {
                passwordInput.type = "password";
                toggleBtn.textContent = "Show";
            }
        });
    }

    // -------------------------
    // Copy Password
    // -------------------------
    if (copyBtn && passwordInput) {
        copyBtn.addEventListener("click", function () {
            const value = passwordInput.value.trim();

            if (!value) {
                alert("Please enter a password first.");
                return;
            }

            navigator.clipboard.writeText(value)
                .then(() => {
                    const oldText = copyBtn.textContent;
                    copyBtn.textContent = "Copied!";
                    setTimeout(() => {
                        copyBtn.textContent = oldText || "Copy";
                    }, 1500);
                })
                .catch(() => {
                    alert("Failed to copy password.");
                });
        });
    }

    // Initial render
    updateStrengthUI();
});
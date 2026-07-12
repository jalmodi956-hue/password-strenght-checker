document.addEventListener("DOMContentLoaded", function () {

    // ==========================================
    // PASSWORD SHOW / HIDE
    // ==========================================

    const passwordInput = document.getElementById("passwordInput");
    const togglePasswordBtn = document.getElementById("togglePasswordBtn");

    if (passwordInput && togglePasswordBtn) {
        togglePasswordBtn.addEventListener("click", function () {
            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                togglePasswordBtn.textContent = "🙈";
            } else {
                passwordInput.type = "password";
                togglePasswordBtn.textContent = "👁";
            }
        });
    }


    // ==========================================
    // LIVE PASSWORD REQUIREMENTS
    // ==========================================

    const lengthCheck = document.getElementById("lengthCheck");
    const upperCheck = document.getElementById("upperCheck");
    const lowerCheck = document.getElementById("lowerCheck");
    const numberCheck = document.getElementById("numberCheck");
    const specialCheck = document.getElementById("specialCheck");

    function updateRequirement(element, passed, text) {
        if (!element) return;

        if (passed) {
            element.innerHTML = "✅ " + text;
            element.classList.add("text-success");
            element.classList.remove("text-danger");
        } else {
            element.innerHTML = "❌ " + text;
            element.classList.add("text-danger");
            element.classList.remove("text-success");
        }
    }

    if (passwordInput) {
        passwordInput.addEventListener("input", function () {
            const password = passwordInput.value;

            updateRequirement(
                lengthCheck,
                password.length >= 8,
                "At least 8 characters"
            );

            updateRequirement(
                upperCheck,
                /[A-Z]/.test(password),
                "Uppercase letter"
            );

            updateRequirement(
                lowerCheck,
                /[a-z]/.test(password),
                "Lowercase letter"
            );

            updateRequirement(
                numberCheck,
                /[0-9]/.test(password),
                "Number"
            );

            updateRequirement(
                specialCheck,
                /[^A-Za-z0-9]/.test(password),
                "Special character"
            );
        });
    }


    // ==========================================
    // COPY GENERATED PASSWORD
    // ==========================================

    const copyPasswordBtn = document.getElementById("copyPasswordBtn");
    const generatedPassword = document.getElementById("generatedPassword");

    if (copyPasswordBtn && generatedPassword) {
        copyPasswordBtn.addEventListener("click", async function () {
            try {
                await navigator.clipboard.writeText(
                    generatedPassword.value
                );

                const oldText = copyPasswordBtn.innerHTML;

                copyPasswordBtn.innerHTML = "✅ Copied";

                setTimeout(function () {
                    copyPasswordBtn.innerHTML = oldText;
                }, 2000);

            } catch (error) {
                alert("Unable to copy password.");
            }
        });
    }


    // ==========================================
    // DELETE HISTORY CONFIRMATION
    // ==========================================

    const deleteForms = document.querySelectorAll(".delete-history-form");

    deleteForms.forEach(function (form) {
        form.addEventListener("submit", function (event) {
            const confirmed = confirm(
                "Are you sure you want to delete this scan?"
            );

            if (!confirmed) {
                event.preventDefault();
            }
        });
    });


    // ==========================================
    // CLEAR HISTORY CONFIRMATION
    // ==========================================

    const clearHistoryForm = document.getElementById("clearHistoryForm");

    if (clearHistoryForm) {
        clearHistoryForm.addEventListener("submit", function (event) {
            const confirmed = confirm(
                "Are you sure you want to clear all scan history?"
            );

            if (!confirmed) {
                event.preventDefault();
            }
        });
    }


    // ==========================================
    // ADMIN DELETE USER CONFIRMATION
    // ==========================================

    const deleteUserForms = document.querySelectorAll(".delete-user-form");

    deleteUserForms.forEach(function (form) {
        form.addEventListener("submit", function (event) {
            const confirmed = confirm(
                "Delete this user and all related scan data?"
            );

            if (!confirmed) {
                event.preventDefault();
            }
        });
    });


    // ==========================================
    // AUTO HIDE FLASH MESSAGES
    // ==========================================

    const flashMessages = document.querySelectorAll(".alert-dismissible");

    flashMessages.forEach(function (message) {
        setTimeout(function () {
            const bootstrapAlert =
                bootstrap.Alert.getOrCreateInstance(message);

            bootstrapAlert.close();
        }, 5000);
    });


    // ==========================================
    // FORM SUBMIT LOADING STATE
    // ==========================================

    const scanForm = document.querySelector(
        'form[action=""], form[data-scan-form]'
    );

    if (scanForm) {
        scanForm.addEventListener("submit", function () {
            const submitButton = scanForm.querySelector(
                'button[type="submit"]'
            );

            if (submitButton) {
                submitButton.disabled = true;
                submitButton.innerHTML =
                    "🔍 Analyzing Security...";
            }
        });
    }

});
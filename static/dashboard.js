console.log("js is loaded");

const CACHE_NAME = 'form-data-cache';
const FORM_DATA_KEY = `/form-data/${USERNAME}`;
let timeout;

function resetTimer(expiration) {
    clearTimeout(timeout);
    const currentTime = new Date().getTime();
    const timeUntilExpiration = (expiration - currentTime)/2000;

    console.log("Current time:", currentTime);
    console.log("Expiration time:", expiration);
    console.log("Time until expiration:", timeUntilExpiration);

    if (timeUntilExpiration <= 0) {
        console.log("Token expired. Logging out...");
        logout();
    } else {
        timeout = setTimeout(logout, timeUntilExpiration);
        console.log("Timeout set for", timeUntilExpiration/1000, "seconds.");
    }
}

function logout() {
    document.getElementById('logoutForm').submit();
}

function handleLogoutAll() {
    document.getElementById('logoutAllForm').submit();
}

async function saveFormData() {
    const cache = await caches.open(CACHE_NAME);
    const formData = {
        name: document.getElementById('name').value,
        email: document.getElementById('email').value,
        phone: document.getElementById('phone').value,
        textField: document.getElementById('textField').value,
        username: USERNAME
    };
    const response = new Response(JSON.stringify(formData), {
        headers: { 'Content-Type': 'application/json' }
    });
    await cache.put(FORM_DATA_KEY, response);
}

async function checkForCachedData() {
    const cache = await caches.open(CACHE_NAME);
    const cachedResponse = await cache.match(FORM_DATA_KEY);
    if (cachedResponse) {
        document.getElementById('retrieveLink').style.display = 'inline';
    } else {
        document.getElementById('retrieveLink').style.display = 'none';
    }
}

async function retrieveFormData() {
    const cache = await caches.open(CACHE_NAME);
    const cachedResponse = await cache.match(FORM_DATA_KEY);
    if (cachedResponse) {
        const formData = await cachedResponse.json();
        if (formData.username === USERNAME) {
            document.getElementById('name').value = formData.name || '';
            document.getElementById('email').value = formData.email || '';
            document.getElementById('phone').value = formData.phone || '';
            document.getElementById('textField').value = formData.textField || '';
        } else {
            alert("No unsaved data found for this user.");
        }
    } else {
        alert("No unsaved data found in cache storage.");
    }
}

window.onload = function() {
    resetTimer(EXPIRATION);

    checkForCachedData();

    document.getElementById('name').addEventListener('input', saveFormData);
    document.getElementById('email').addEventListener('input', saveFormData);
    document.getElementById('phone').addEventListener('input', saveFormData);
    document.getElementById('textField').addEventListener('input', saveFormData);
    document.getElementById('fileInput').addEventListener('change', saveFormData);
};

document.onmousemove = function() { resetTimer(EXPIRATION); };
document.onkeydown = function() { resetTimer(EXPIRATION); };
document.ontouchstart = function() { resetTimer(EXPIRATION); };
document.ontouchmove = function() { resetTimer(EXPIRATION); };

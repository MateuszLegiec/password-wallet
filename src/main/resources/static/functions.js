const PASSWORD_WALLET_TOKEN_NAME = 'PASSWORD_WALLET_TOKEN';
const PASSWORD_WALLET_TOKEN = sessionStorage.getItem(PASSWORD_WALLET_TOKEN_NAME);
const IS_USER_LOGGED_IN = PASSWORD_WALLET_TOKEN != null;
const BASE_URL = "http://localhost:8080";

if (IS_USER_LOGGED_IN) {
    login(PASSWORD_WALLET_TOKEN)
}

function username() {
    return atob(sessionStorage.getItem(PASSWORD_WALLET_TOKEN_NAME).substring(6)).split(':')[0];
}

function token() {
    return sessionStorage.getItem(PASSWORD_WALLET_TOKEN_NAME);
}

function login(token, displayAlert = false) {
    fetch(
        BASE_URL + "/login",
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token
            },
            method: "GET"
        }
    ).then(response => {
            if (response.ok) {
                sessionStorage.setItem(PASSWORD_WALLET_TOKEN_NAME, token)
                if (location.href !== 'http://localhost:8080/wallet.html') {
                    location.href = 'http://localhost:8080/wallet.html'
                }
            } else {
                if (displayAlert) {
                    alert("UNAUTHORIZED")
                }
                sessionStorage.removeItem(PASSWORD_WALLET_TOKEN_NAME)
            }
        }
    )
}

function logout() {
    sessionStorage.removeItem(PASSWORD_WALLET_TOKEN_NAME)
    location.href = BASE_URL
}

function changePassword(oldPassword, newPassword) {
    fetch(
        `${BASE_URL}/${username()}/change-password`,
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token()
            },
            method: "POST",
            body: JSON.stringify({
                    "oldPassword": oldPassword,
                    "newPassword": newPassword
                }
            )
        }
    )
        .then(data => {
                if (data.status === 200) {
                    location.href = BASE_URL
                } else {
                    console.error(data.body)
                }
            }
        )
}

function register(username, password, hash) {
    fetch(
        `${BASE_URL}/register`,
        {
            headers: {
                "Content-Type": "application/json",
                "Authorization": token()
            },
            method: "POST",
            body: JSON.stringify(
                {
                    "username": username,
                    "password": password,
                    "hashFunction": hash
                }
            )
        }
    )
        .then(data => {
                if (data.ok) {
                    location.href = BASE_URL
                } else {
                    console.log(data)
                    console.error(data.body)
                }
            }
        )
}

function putWalletItem(webAddress, webAddressUsername, webAddressPassword) {
    fetch(
        `${BASE_URL}/${username()}/wallet-items/${webAddress}`,
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token()
            },
            method: "PUT",
            body: JSON.stringify({
                "webAddressUsername": webAddressUsername,
                "webAddressPassword": webAddressPassword
            })
        }
    )
        .then(data => {
                if (data.ok) {
                    getWalletItems();
                } else {
                    console.error(data)
                }
            }
        )
}

function decodeWalletItemPassword(webAddress) {
    fetch(
        `${BASE_URL}/${username()}/wallet-items/${webAddress}/password`,
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token()
            },
            method: "GET"
        }
    )
        .then(res => res.text())
        .then(data => document.getElementById(`${webAddress}_password`).innerText = data)
}

function getWalletItems() {
    fetch(
        `${BASE_URL}/${username()}/wallet-items`,
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token()
            },
            method: "GET"
        }
    )
        .then(res => res.json())
        .then(data => document.getElementById('walletItems').innerHTML = data
            .map(
                it => `
<div>
Web address: ${it.webAddress}, 
Username: ${it.webAddressUsername}, 
Password: <span style="cursor: pointer;" id="${it.webAddress}_password" onclick="decodeWalletItemPassword('${it.webAddress}')">???</span>
</div>
`)
            .join('')
        )
}

function unlockIp(ip){
    fetch(
        `${BASE_URL}/blocked-ips/${ip}`,
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token()
            },
            method: "DELETE",
        }
    )
        .then(data => {
                if (data.ok) {
                    getBlockedIps();
                } else {
                    console.error(data)
                }
            }
        )
}

function getBlockedIps() {
    fetch(
        `${BASE_URL}/blocked-ips`,
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token()
            },
            method: "GET"
        }
    )
        .then(res => res.json())
        .then(data => document.getElementById('blockedIps').innerHTML = data
            .map(
                it => `
<div>${it} <button id="${it}_button" onclick="unlockIp('${it}')">UNLOCK</button>
</div>
`)
            .join('')
        )
}

function getLoginAudits() {
    fetch(
        `${BASE_URL}/${username()}/login-audits`,
        {
            headers: {
                "Content-Type": "application/json; charset=UTF-8",
                "Authorization": token()
            },
            method: "GET"
        }
    )
        .then(res => res.json())
        .then(data => document.getElementById('loginAudits').innerHTML = data
            .map(
                it => `
<div>
ip: ${it.ipAddress}, 
result: ${it.operationResult}, 
date: ${it.creationDate}
</div>
`)
            .join('')
        )
}


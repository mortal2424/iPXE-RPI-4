import RFB from "/novnc/core/rfb.js";

const screen = document.querySelector("#screen");
const status = document.querySelector("#status");
const credentials = document.querySelector("#credentials");
const password = document.querySelector("#password");
const retry = document.querySelector("#retry");
let rfb;
let rejected;

function connect() {
    rejected = false;
    status.textContent = "Подключение…";
    retry.hidden = true;
    credentials.hidden = true;
    const socket = new URL(location.pathname + "/socket", location.href);
    socket.protocol = "wss:";
    rfb = new RFB(screen, socket.href, {wsProtocols: ["binary"]});
    rfb.scaleViewport = true;
    rfb.addEventListener("credentialsrequired", () => {
        credentials.hidden = false;
        status.textContent = "Введите пароль VNC";
        password.focus();
    });
    rfb.addEventListener("connect", () => {
        status.textContent = "Консоль подключена";
        credentials.hidden = true;
    });
    rfb.addEventListener("disconnect", (event) => {
        credentials.hidden = true;
        retry.hidden = false;
        if (rejected) return;
        status.textContent = event.detail.clean ? "Соединение закрыто" :
            "Не удалось подключиться. Проверьте SSH и службу VNC на Pi.";
    });
    rfb.addEventListener("securityfailure", () => {
        rejected = true;
        status.textContent = "Сервер отклонил пароль VNC";
    });
}

credentials.addEventListener("submit", (event) => {
    event.preventDefault();
    rfb.sendCredentials({password: password.value});
    password.value = "";
});
retry.addEventListener("click", connect);
connect();

// static/js/notifications.js

document.addEventListener('DOMContentLoaded', function() {
    // Buscamos los elementos en el DOM
    const badge = document.getElementById('incidencias-badge');
    const audioContainer = document.getElementById('audio-container');
    
    // Si no estamos en una página con notificaciones, no hacemos nada.
    if (!badge || !audioContainer) return;

    // Obtenemos las rutas de los audios desde los atributos data-* del HTML
    const notificationSoundSrc = audioContainer.dataset.notificationSound;
    const silentSoundSrc = audioContainer.dataset.silentSound;

    const audioNotification = new Audio(notificationSoundSrc);
    const audioUnlocker = new Audio(silentSoundSrc);
    
    let audioUnlocked = false;

    function unlockAudio() {
        if (audioUnlocked) return;
        
        audioUnlocker.play().then(() => {
            audioUnlocked = true;
            console.log("Permiso de audio obtenido silenciosamente.");
            document.body.removeEventListener('click', unlockAudio);
            document.body.removeEventListener('keydown', unlockAudio);
        }).catch(error => {
            console.warn("Intento de desbloqueo de audio no fue necesario o falló:", error);
        });
    }

    document.body.addEventListener('click', unlockAudio, { once: true });
    document.body.addEventListener('keydown', unlockAudio, { once: true });

    let currentCount = 0;
    const checkUrl = audioContainer.dataset.checkUrl; // URL para la API

    function checkIncidencias() {
        fetch(checkUrl)
            .then(response => {
                if (!response.ok) {
                    console.error('Error al chequear incidencias. Deteniendo notificaciones.');
                    clearInterval(pollingInterval);
                    return Promise.reject('Respuesta de servidor no OK');
                }
                return response.json();
            })
            .then(data => {
                if (data && data.pendientes !== undefined) {
                    const newCount = data.pendientes;
                    if (newCount > currentCount) {
                        console.log("¡Nueva incidencia detectada! Intentando reproducir sonido de notificación...");
                        if (audioUnlocked) {
                           audioNotification.volume = 0.7;
                           audioNotification.play().catch(e => console.error("La reproducción del sonido de notificación falló:", e));
                        }
                    }
                    currentCount = newCount;
                    updateBadge(currentCount);
                }
            })
            .catch(error => {
                console.error('Error en la red o en el proceso de chequeo:', error);
            });
    }

    function updateBadge(count) {
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'block';
        } else {
            badge.style.display = 'none';
        }
    }

    checkIncidencias();
    const pollingInterval = setInterval(checkIncidencias, 20000);
});
document.addEventListener('DOMContentLoaded', function() {
    // --- Buscamos todos los elementos necesarios ---
    const audioContainer = document.getElementById('audio-container');
    if (!audioContainer) return;

    // Contadores para cada tipo de incidencia
    const pickingBadge = document.getElementById('picking-incidencias-badge');
    const entregaBadge = document.getElementById('entrega-incidencias-badge');

    // URLs de las APIs
    const checkUrlPicking = audioContainer.dataset.checkUrlPicking;
    const checkUrlEntregas = audioContainer.dataset.checkUrlEntregas;
    
    const audioNotification = new Audio(audioContainer.dataset.notificationSound);
    
    // Guardamos los conteos actuales para detectar cambios
    let currentPickingCount = -1;
    let currentEntregaCount = -1;

    // --- Función genérica para chequear una API y actualizar un badge ---
    function checkApi(url, badgeElement, currentCountRef) {
        if (!url || !badgeElement) return;

        fetch(url)
            .then(response => response.ok ? response.json() : Promise.reject('Respuesta no OK'))
            .then(data => {
                if (data && data.pendientes !== undefined) {
                    const newCount = data.pendientes;
                    
                    // Si es la primera vez, solo actualizamos
                    if (currentCountRef.value === -1) {
                        currentCountRef.value = newCount;
                    } 
                    // Si el nuevo conteo es mayor, reproducimos sonido
                    else if (newCount > currentCountRef.value) {
                        console.log(`¡Nueva incidencia detectada en ${url}!`);
                        audioNotification.volume = 0.7;
                        audioNotification.play().catch(e => console.error("La reproducción del sonido falló:", e));
                    }
                    
                    currentCountRef.value = newCount;
                    updateBadge(badgeElement, currentCountRef.value);
                }
            })
            .catch(error => {
                console.error(`Error chequeando ${url}:`, error);
            });
    }

    // --- Función para actualizar la apariencia del badge ---
    function updateBadge(badge, count) {
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }
    }

    // --- Bucle principal ---
    function checkAllIncidencias() {
        // Usamos objetos para pasar el conteo por referencia
        checkApi(checkUrlPicking, pickingBadge, { value: currentPickingCount });
        checkApi(checkUrlEntregas, entregaBadge, { value: currentEntregaCount });
    }

    // --- Inicio ---
    // El desbloqueo de audio no es necesario aquí, ya que el sonido
    // solo se reproduce para el admin/operario que ya está interactuando.
    
    checkAllIncidencias(); // Chequeo inmediato al cargar la página
    setInterval(checkAllIncidencias, 20000); // Y luego cada 20 segundos
});
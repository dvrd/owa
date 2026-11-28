# Dos notas de voz de un chat privado

El ejemplo Odin se integra en el bucle de eventos de una aplicación ya vinculada. Todos los procedimientos del socket se llaman desde su propietario. El JID que autoriza la captura lo elige el consumidor.

## Consultar la conversación

Para localizar la pregunta, pide una página con `socket_fetch_recent_chat_history(socket, chat, id_segunda)`. Owa envía `INITIAL_REVERSE_HISTORY` al dispositivo principal sin cursor. El ID se compara **localmente** contra las respuestas entrantes de ese chat.

Cuando ya conoces el ID exacto de una nota entrante, llama a `socket_fetch_private_message_by_id(socket, chat, id)`. El ejemplo `download_voice` usa esta operación si falta el descriptor local. Envía al dispositivo principal de la cuenta una solicitud `PLACEHOLDER_MESSAGE_RESEND` con la clave original (chat, dirección entrante e ID). El protocolo la contempla para mensajes que el cliente no pudo descifrar. La prueba real descrita abajo recuperó una nota antigua ya procesada. [Solicitud de referencia](https://github.com/tulir/whatsmeow/blob/main/send.go) · [Recepción de la respuesta](https://github.com/tulir/whatsmeow/blob/main/message.go)

| Solicitud al teléfono | Datos de la petición | Evidencia con un teléfono vinculado |
| --- | --- | --- |
| Página inicial | Chat, cantidad y modo inicial sin referencia | En la prueba real devolvió `Query_Timeout` a los 60 segundos. En el mismo socket, la consulta anterior a la nota devolvió 50 mensajes. Sigue sin conocerse la causa del silencio del teléfono. |
| Página anterior | Chat, cantidad, clave y hora de la referencia | Respondió con 50 mensajes. Incluyó la pregunta y la primera nota. La segunda era la referencia y quedó fuera. |
| Mensaje por ID | Clave de la nota, sin hora ni cursor | Dos consultas aisladas (PN y LID) agotaron 60 segundos. En otra conexión, inmediatamente después de recibir una página anterior a la nota, la consulta por ID con PN recibió acuse, recibo y una respuesta cifrada. Owa descifró el control tipo 17, correlacionó la operación 4 y descargó el audio. Los bytes coincidieron con la copia independiente. |

Si la consulta por ID devuelve un mensaje, el consumidor asume su propiedad y lo libera con `socket_message_destroy`. Owa acepta la respuesta del dispositivo principal propio, comprueba el identificador de solicitud y compara chat (o alias conocido), dirección e ID. La copia se entrega al solicitante sin reinsertarla en el inbox. Un timestamp cero indica que la copia carece de hora original utilizable.

La función del ejemplo `voices_after_question(page, pregunta)` encuentra una pregunta saliente única y las dos primeras notas entrantes posteriores que contiene esa página. Indica si falta la pregunta, faltan notas o el orden es ambiguo.

En una respuesta correcta, recorre `page.messages`. Reconoce la pregunta saliente por su ID o con `text_message_decode(m.protobuf)`, y cada nota entrante con `media_message_decode(m.protobuf)`, `.Audio` y `voice_note`. Conserva el orden entregado por el teléfono y las horas originales, y usa la clave (chat, dirección, ID) para deduplicar entre páginas. En el fixture el teléfono devuelve primero lo más nuevo. Dos mensajes del mismo segundo pueden compartir timestamp. El ID es opaco y no determina cuál fue primero.

`page.oldest` y `page.newest` delimitan lo observado por hora original. Pueden ser nil en una página vacía. `page.target` apunta al mensaje solicitado si llegó. Ninguno de estos punteros sobrevive a la destrucción de los mensajes. Si la pregunta es anterior, pide otra página con `socket_fetch_chat_history` pasando el ID, timestamp y dirección del mensaje más antiguo recibido. Detén la búsqueda si una página está vacía, el cursor se repite o alcanzas el límite de páginas de tu aplicación.

La API anterior conserva su comportamiento. Una referencia explícita pide mensajes anteriores. Al omitirla, usa el cursor local más nuevo del chat o su alias, incluidos envíos antiguos con hora original en Outbound_Content. Sin referencia conocida pide historial inicial. El cursor entrante se actualiza cuando `track_chat_history_cursors` está habilitado. Una página llena, incluso de 50 mensajes, sólo describe ese intervalo.

En la ejecución exitosa, ambas consultas usaron el mismo socket. La página anterior contenía la primera nota. El descriptor de la segunda llegó en la respuesta por clave. La prueba no estableció si la consulta previa despertó al teléfono o si influyó otra condición de entrega.

## Recibir y confirmar

1. En el evento entrante, owa ya guardó el protobuf y los metadatos en Inbox_Message junto con el avance de Signal. El ACK del protocolo y la confirmación del trabajo de la aplicación son operaciones distintas.
2. Para chats seleccionados, guarda en el índice de tu aplicación el chat, la dirección, el ID y la hora original en un *upsert* duradero. Guarda también la relación con la pregunta si la aplicación debe reconstruirla tras reiniciar. Al recibir audio llama a `complete_selected_audio` con el JID autorizado. Completa otros eventos con `socket_message_complete` cuando su trabajo sea duradero. Al fallar la escritura conserva el evento pendiente y reintenta; destruir el objeto del evento sólo libera su memoria.
3. La confirmación con captura guarda el protobuf de audio y su timestamp original, crea la marca de procesamiento y retira el inbox en una transacción. Conserva hasta 64 entradas para toda la sesión, en orden de inserción y de hasta 64 KiB cada una, incluyendo los ocho bytes de hora. Al insertar la número 65 se retira la más antigua. El snapshot contiene material sensible. Guárdalo con acceso privado. La confirmación normal sólo conserva la marca de deduplicación y los demás registros de sesión que ya mantenía owa.
4. Tras reiniciar, llama a `load_private_audio(store, chat, id)`. El mensaje devuelto posee sus datos. Destrúyelo con `socket_message_destroy`. Para descargar usa `socket_download_media`, que necesita el localizador CDN, la clave, la longitud y los hashes del medio. Una marca de procesamiento ordinaria contiene ocho bytes de hora **local** y no suministra ninguno de esos campos. El ejemplo no almacena los bytes descargados.

| Resultado | Interpretación |
| --- | --- |
| Consulta local correcta con mensaje nil | Falta el descriptor local o ya fue desalojado. |
| Consulta al teléfono con Query_Timeout | No se completó una respuesta correlacionada durante el plazo. Se puede volver a consultar. |
| Página recibida con target nil | El mensaje falta en esa página. Su disponibilidad en el teléfono sigue abierta. |
| Consulta por ID correcta con mensaje nil | El teléfono respondió a esa solicitud y la respuesta no contenía una copia coincidente. |
| Descarga con Media_Failed | Examina media.kind y, para HTTP, media.status. Un fallo de hash, autenticación o descifrado invalida los bytes. |
| Descarga correcta | Usa únicamente los primeros n bytes del destino. |

## Aceptación con dos cuentas de prueba

1. Usa dos cuentas propias A y B y un cliente vinculado a A. Prepara dos sesiones vinculadas independientes antes de la prueba, o repite con dos chats de prueba separados. Mantén privada la ruta de estado de cada cliente, fuera del repositorio. En el cliente de captura autoriza sólo B. En el antiguo usa la confirmación normal. Para el control de cursor antiguo, guarda primero una referencia original del día anterior y desactiva el seguimiento posterior de cursores en ese cliente.
2. Desde A envía una pregunta sintética. Desde B responde dos textos breves y graba dos notas distintas. Deja la segunda como último mensaje durante **todas** las consultas. En B conserva de forma privada ambos archivos de audio enviados, en su codificación original, y calcula su SHA-256 antes de la descarga de prueba. Un hash tomado del descriptor recibido no constituye la referencia independiente. Mantén IDs, horas, JIDs, hashes y archivos fuera de los logs y de Git.
3. En el cliente de captura procesa cada evento con el paso anterior. Cierra y vuelve a abrir el cliente usando su mismo estado durable. Carga ambos IDs, descarga ambas notas y compara localmente longitud y SHA-256 contra los archivos de B. Confirma que hay dos IDs distintos, que cada uno se recupera una vez y que conservan su orden original.
4. En el cliente antiguo confirma que la búsqueda local del segundo ID devuelve nil, que su marca mide ocho bytes y que no tiene audio en caché. Anota por separado el intervalo de la consulta automática, de la consulta anterior a la primera nota y de la consulta anterior a la segunda (usa sus horas originales). Ejecuta `download_voice` para el segundo ID mientras sigue siendo el último. Registra sólo el resultado, la cantidad y si coincidieron los bytes. Una omisión o un timeout deja abierta la recuperación histórica.
5. Repite la consulta reciente con el alias LID ya mapeado. Con el teléfono temporalmente desconectado comprueba el timeout; reconéctalo y repite en el mismo socket. En un chat sintético sin captura, confirma un audio y reinicia: la búsqueda local debe devolver nil. Para el informe basta con publicar resultados agregados y versiones.

Para ejecutar los controles sintéticos desde la raíz usa `task check`. Los fixtures incluyen una página antigua completa, la secuencia pregunta/textos/notas, ciphertexts sintéticos y los bytes esperados independientes. Los resultados del teléfono se deben informar por separado.

Para comparar archivos sin imprimir contenido, claves ni hashes, pon las dos referencias de B y las dos descargas en un directorio privado fuera de Git, con nombres neutros. Ejecuta allí:

```sh
cmp -s referencia-1.ogg captura-1.ogg &&
cmp -s referencia-2.ogg captura-2.ogg &&
cmp -s referencia-2.ogg historica-2.ogg
```

Un estado de salida cero verifica las tres comparaciones byte a byte. Ejecuta la tercera por separado si la sesión antigua recibió una página incompleta o agotó el tiempo de espera; registra primero si llegó a producir un archivo.

### Consulta directa frente a consulta precedida por historial

En cuatro conexiones nuevas a una misma sesión vinculada se solicitó por ID la segunda nota. En las dos conexiones centrales se pidió primero una página anterior usando la propia nota como referencia y su hora local de procesamiento, la única hora disponible en esa sesión antigua. Ambas páginas devolvieron 50 mensajes e incluyeron la primera nota. Nadie envió otro mensaje al chat durante las consultas.

| Orden | Solicitud previa | Acuse (s) | Recibo (s) | Respuesta por ID (s) | Bytes verificados (s) |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Ninguna | 0.18 | 1.26 | 1.33 | 1.68 |
| 2 | Historial | 0.15 | 0.66 | 0.74 | 0.84 |
| 3 | Historial | 0.08 | 0.46 | 0.52 | 0.69 |
| 4 | Ninguna | 0.08 | 0.57 | 0.63 | 0.79 |

Los tiempos parten del envío de la solicitud por ID. Incluyendo la página previa, las pruebas 2 y 3 tardaron 2.68 y 1.88 segundos desde la conexión hasta la comparación. Las cuatro descargas coincidieron byte por byte con la referencia independiente de 137908 bytes. En ese teléfono bastó la consulta directa. Las consultas fueron consecutivas y el estado físico del teléfono no se controló. Sigue pendiente explicar los timeouts de las consultas anteriores.

Para repetir con control del teléfono, usa la misma clave y referencia privada en tres rondas. En la primera mantén WhatsApp en primer plano, en la segunda déjalo en segundo plano y en la tercera desconecta el teléfono de la red. En cada ronda alterna consulta directa y consulta precedida por historial, desde conexiones nuevas y con el mismo plazo. Anota por separado el tiempo de la página, el del acuse, el del recibo, el de la respuesta correlacionada y el de la comparación. Tras el timeout sin red, reconecta el teléfono y repite por ID en el mismo socket. Registra cualquier cambio de estado durante la ronda.

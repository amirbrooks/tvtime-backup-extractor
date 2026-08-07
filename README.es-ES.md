

# TV Time Backup Extractor

Recupere títulos, favoritos, episodios en caché, eventos de visualización y referencias multimedia legibles de TV Time desde una copia de seguridad local cifrada autorizada de iPhone o iPad. El extractor lee la copia de seguridad completada, copia solo los archivos coincidentes del dominio de la aplicación TV Time en un destino privado nuevo y produce informes legibles por humanos junto con tablas CSV detalladas.

El proyecto es gratuito y de código abierto. iMazing no es requerido. No modifica el teléfono ni la copia de seguridad de origen, no contacta a TV Time, no restaura datos a la aplicación y no proporciona una exportación oficial de cuenta en la nube.

> **Estado de lanzamiento:** [v0.2.0](https://github.com/amirbrooks/tvtime-backup-extractor/releases/tag/v0.2.0) sigue siendo el lanzamiento estable más reciente. El candidato `v0.3.1-alpha.1` añade una compilación de prueba descargable para Windows x64 junto con paquetes actualizados para Mac y Python. Aún no se ha publicado. La recuperación para Windows, Android y la exportación oficial siguen siendo experimentales.

El [registro de lanzamiento v0.3.1-alpha.1](docs/release-v0.3.1-alpha.1.md) enumera las pruebas requeridas y los límites específicos del dispositivo que permanecen.

Este proyecto es independiente y no está afiliado ni respaldado por TV Time ni Apple. TV Time y las marcas relacionadas pertenecen a sus respectivos propietarios. Úselo solo con datos que usted posea o tenga autorización para acceder, y cumpla con la legislación aplicable y los términos del servicio.

## Elija una ruta

| Ruta | Ideal para | Requisitos |
| --- | --- | --- |
| Aplicación nativa de macOS | La mayoría de los usuarios de Mac | macOS 14 o posterior y el DMG v0.2.0 que coincida con la arquitectura del Mac |
| Recuperación por CLI de Python | macOS, Linux, automatización y desarrollo | Python 3.10 a 3.13 seleccionado explícitamente más las dependencias fijadas |
| Aplicación alfa para Windows | Pruebas de recuperación de iOS cifrado, Android local y exportación | Windows x64, BitLocker o cifrado de dispositivo, y el paquete firmado para probadores alfa |
| Recuperación de Android/exportación | Usuarios de Mac, Windows o CLI con una fuente ya preservada | Copia de seguridad heredada compatible, instantánea en lista permitida o exportación oficial ZIP/CSV |

La aplicación nativa publicada es la instalación normal para Mac:

- Los Mac con chip Apple utilizan el DMG `Apple-Silicon-arm64`;
- Los Mac con Intel utilizan el DMG `Intel-x86_64`; y
- los usuarios finales no necesitan Python, iMazing, Homebrew, Git, GitHub CLI ni herramientas de desarrollo de Apple.

Descárguelo desde el [lanzamiento oficial v0.2.0](https://github.com/amirbrooks/tvtime-backup-extractor/releases/tag/v0.2.0). Consulte la [guía de macOS](docs/macos.md) para la instalación y el [registro de lanzamiento v0.2.0](docs/release-v0.2.0.md) para los controles de distribución completados.

## Requisitos de recuperación

Cada ruta requiere una fuente local controlada por el propietario, almacenamiento de salida local privado y espacio libre suficiente para el procesamiento y los informes.

La recuperación de iOS o iPadOS cifrado también requiere una copia de seguridad local cifrada completada realizada con Finder, Apple Devices o iTunes, su contraseña de cifrado, y el teléfono desconectado y expulsado de forma segura después de confirmar la finalización de la copia de seguridad. La recuperación no duplica toda la copia de seguridad del dispositivo.

Las rutas de Android y exportación oficial usan su propia fuente local seleccionada. No requieren una copia de seguridad de iOS ni su contraseña.

El desbloqueo de root de un teléfono, eludir la política de copia de seguridad de Android, la extracción de cuentas en la nube y la restauración de datos recuperados en TV Time no son compatibles. Las aplicaciones modernas de versiones de Android deshabilitan comúnmente la copia de seguridad heredada; la herramienta informa esa limitación en lugar de eludirla.

## Flujo de trabajo de la aplicación nativa de macOS

La aplicación publicada es compatible con macOS 14 o posterior:

1. Descargue el DMG para **Apple silicon** o **Intel** desde la página de lanzamientos del proyecto y verifique su suma de verificación publicada.
2. Abra el DMG, arrastre **TV Time Backup Extractor** a **Applications** (Aplicaciones), expulse el DMG y abra la aplicación desde Aplicaciones.
3. Elija la carpeta de copia de seguridad de Apple. Si contiene una copia de seguridad completada, la aplicación la selecciona automáticamente. Si aparecen varias copias, abra la deseada antes de seleccionarla.
4. La aplicación crea una carpeta de recuperación nueva en el almacenamiento local privado gestionado por la aplicación. No hay selector de destino, requisito de imagen de disco montada ni ruta de usuario codificada.
5. Revise el control previo de solo lectura: estado de cifrado, estado de instantánea finalizada, fecha y tamaño de la copia de seguridad, tamaño del manifiesto, espacio libre local y espacio de trabajo mínimo.
6. Ingrese la contraseña de la copia de seguridad en el campo seguro y reconozca que los informes recuperados son texto sin formato legible en este Mac. FileVault sigue siendo recomendado para protección completa del disco.
7. Inicie la recuperación y mantenga el Mac despierto hasta que aparezca la pantalla de resultados.
8. Valide el gráfico agregado y los recuentos, luego abra el informe visual, PDF o Markdown privado, o muestre la carpeta de recuperación gestionada por la aplicación en Finder.

Utilice **Show Previous Recoveries** (Mostrar recuperaciones anteriores) en la primera pantalla para encontrar ejecuciones anteriores completadas o incompletas. Revíselas antes de eliminar cualquier cosa; la aplicación nunca elimina silenciosamente la salida de recuperación.

La contraseña se pasa solo al asistente local incluido y no se escribe intencionalmente en el disco. La aplicación limpia su campo después de iniciar, pero ni Swift ni Python pueden garantizar el borrado inmediato de cada copia en memoria.

Cancelar la verificación de la copia de seguridad no genera salida de recuperación. Cancelar una recuperación activa, cerrar su ventana o salir de la aplicación requiere confirmación. Una cancelación confirmada conserva la salida incompleta para diagnóstico; nunca reutiliza ni elimina silenciosamente esa salida. Cada reintento obtiene un destino nuevo.

La pantalla de resultados nativa completada proporciona:

- un panel de paquete verificado que confirma la estabilidad de la fuente seleccionada, la consistencia del marcador de finalización, la integridad de los archivos copiados y los artefactos de informe sellados;
- un gráfico de barras agregado y recuentos explícitos de películas vistas/guardadas y eventos nombrados/no nombrados;
- resúmenes de archivos copiados y diferencias en el recuento de bytes;
- recuentos agregados de imágenes, tráilers y referencias de URL multimedia;
- un informe visual, un PDF apto para impresión y un catálogo Markdown completo, con una explicación clara cuando se omite el PDF opcional; y
- acciones protegidas para abrir informes o mostrar el directorio de análisis.

Abrir un informe utiliza el navegador predeterminado o el visor de documentos. Su nombre de archivo privado puede aparecer luego en el historial de esa aplicación o en Elementos Recientes de macOS. Consulte [Privacidad y manejo seguro](docs/privacy.md).

## Informes y tablas

Una recuperación completa exitosa crea estos informes principales bajo `TVTime-Extraction/analysis/`:

- `TVTime-Recovered-Data.md`: texto legible canónico que lista cada registro recuperado y cada nombre disponible
- `TVTime-Recovered-Data.html`: informe visual principal accesible y autosuficiente con gráficos y tablas semánticas; funciona sin conexión, no contiene scripts y no solicita multimedia remota
- `TVTime-Recovered-Data.pdf`: complemento opcional apto para impresión generado desde el mismo modelo de informe; utilice el informe HTML para estructura semántica etiquetada con tecnología de asistencia
- `Suite-TV-Liberator-confirmed.zip`: importación de Suite TV que contiene solo el estado de visualización recuperado exacto
- `Suite-TV-Liberator-estimated-progress.zip`: importación alternativa de Suite TV que completa el estado por episodio faltante hasta los recuentos agregados de serie recuperados

Markdown, HTML y PDF se renderizan desde un único modelo de visualización seguro compartido, incluidos marcadores de posición de título faltante idénticos y una sección de diferencias de tamaño de copia cuando los metadatos de la copia de seguridad y los recuentos de bytes copiados no coinciden. Las tablas CSV detalladas permanecen como el archivo exacto; los formatos legibles reemplazan los caracteres de control con espacios, recortan los espacios en blanco circundantes y colapsan las secuencias de espacios en blanco mientras preservan el resto del texto Unicode recuperado.

El PDF se omite deliberadamente cuando la fuente incrustada disponible o el soporte de composición no pueden renderizar fielmente cada carácter recuperado. Esta es una salvaguarda de fidelidad, no una recuperación fallida: el Markdown y el HTML sin conexión permanecen completos. Las tablas CSV normalizadas preservan los datos privados detallados utilizados por los informes, incluidos títulos, favoritos, episodios y eventos de visualización exactos.

Para Suite TV, prefiera `Suite-TV-Liberator-confirmed.zip` cuando la exactitud sea importante. El archivo estimado conserva cada visualización recuperada exacta y nunca estima especiales, pero completa los episodios regulares restantes más antiguos hasta que se alcanza cada recuento agregado de visualización recuperado. No puede reconstruir qué episodios saltados, fuera de orden o vistos repetidamente produjeron ese recuento. Ambos archivos usan el diseño de cinco archivos de TV Time Liberator y se crean completamente sin conexión; las películas sin un identificador TVDB positivo recuperado se omiten porque Suite TV no puede identificarlas de forma segura.

La recuperación completa exitosa tiene dos puntos de control legibles por máquina con versión:

- `metadata/run_state.json` tiene `status` establecido en `complete` después de que finalice la extracción de archivos seleccionados y se vuelva a validar la fuente; y
- `analysis/recovery_state.json` tiene `status` establecido en `complete` en el directorio de informes promovido de forma atómica y vincula el conjunto exacto de artefactos de informe/tabla, recuentos agregados, tamaños de bytes y digestes SHA-256.

No considere una salida como una recuperación completa finalizada si falta alguno de los marcadores esperados o no está completo. El comando independiente `extract` crea intencionalmente solo el marcador de extracción. Nunca edite un marcador ni mezcle archivos de ejecuciones separadas. Consulte la [referencia de salida completa](docs/output-reference.md).

## Modelo de espacio libre

El extractor no duplica la copia de seguridad completa del iPhone o iPad.

El control previo inicial de procesamiento de manifiesto verifica al menos lo mayor de:

- 512 MiB; o
- el doble del tamaño de `Manifest.db` de origen.

Este suelo inicial es suficiente para comenzar el procesamiento seguro del manifiesto; no es el requisito completo de espacio de recuperación. Después de que el manifiesto cifrado identifica los dominios de TV Time, la recuperación requiere la suma de los tamaños declarados de los archivos seleccionados, la carga útil cifrada de origen seleccionada más grande como instantánea de preparación, margen adicional igual a lo mayor de 64 MiB o el 10% de los bytes declarados seleccionados, y un `Manifest.db` retenido solo cuando la opción avanzada de manifiesto descifrado está habilitada. El control post-retención omite esa asignación de manifiesto ya retenida, pero aún incluye la instantánea de preparación más grande.

El tamaño completo de la copia de seguridad mostrado en el control previo es un origen útil; no es el tamaño de destino requerido. Mantenga margen adicional para la asignación del sistema de archivos y reintentos futuros, y no desmonte el destino mientras la recuperación esté activa.

## Alternativa de la CLI de Python

La CLI es gratuita y admite Python 3.10 a 3.13. El candidato privado añade enlazamiento nativo de manipuladores Win32 para archivos de origen cifrados de iOS y salida nueva; use su paquete WinUI para el aislamiento más fuerte en Windows. También añade los comandos `recover-android-backup`, `recover-android-snapshot`, `recover-export`, `android-probe` y el `android-capture` explícitamente reconocido.

### Instalar desde una clonación de origen o ZIP

Descargue el repositorio como un ZIP de origen, o clónelo si Git ya está disponible. Git es opcional. Desde el directorio del proyecto en macOS o Linux:

```text
python3.13 -m venv .venv
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
./.venv/bin/python -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
./.venv/bin/python -m pip install --no-index --no-build-isolation --no-deps .
./.venv/bin/python -m pip check
./.venv/bin/python -m tvtime_extractor --version
```

En Windows PowerShell:

```text
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements.lock
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --requirement requirements-source-build.lock
.venv\Scripts\python.exe -m pip install --no-index --no-build-isolation --no-deps .
.venv\Scripts\python.exe -m pip check
.venv\Scripts\python.exe -m tvtime_extractor --version
```

Las versiones de las dependencias y los artefactos descargables están fijados. `requirements.lock` contiene hashes para las ruedas compatibles con macOS, Windows y Linux; la instalación rechaza un artefacto no listado y nunca construye una dependencia desde el origen. El backend mínimo de compilación de origen está fijado por hash por separado, y la instalación final del proyecto local deshabilita el aislamiento de compilación y el índice de paquetes para que no pueda obtener una herramienta de compilación no declarada. Los entornos virtuales no son portátiles entre carpetas o equipos; cree uno nuevo si el proyecto se mueve.

### Ejecutar una recuperación completa

Utilice una carpeta de copia de seguridad individual y una ruta de ejecución de destino que aún no exista. El padre inmediato de la salida cifrada ya debe existir; el hijo de ejecución nueva en sí no debe existir. Esta regla de 'padre-existente/hijo-no-existente' también se aplica en Windows. La versión pública v0.2.0 aún no tiene aplicación de recuperación para Windows; el candidato privado usa el paquete nativo documentado a continuación. En macOS o Linux:

```text
./.venv/bin/python -m tvtime_extractor recover \
  --backup "/path/to/DEVICE_BACKUP" \
  --output "/path/to/PRIVATE_NEW_RUN" \
  --acknowledge-sensitive-output
```

La CLI completa y resume visiblemente el control previo completo de solo lectura de copia de seguridad/destino antes de que aparezca la solicitud de contraseña oculta. Consume el mismo recibo de identidad de origen después de la solicitud, luego mantiene las identidades del directorio padre seleccionado y la raíz de salida nueva a lo largo de la recuperación. Una raíz de copia de seguridad reemplazada, metadatos críticos vinculados cambiados o un agregado de fuente mostrado cambiado fallan antes de la creación de la salida; los archivos de carga seleccionados se verifican por instantánea durante la extracción y se vuelven a validar antes de completar la extracción. Los descendientes POSIX permanecen relativos al directorio de trabajo con raíz en el descriptor. Los comandos independientes `analyze` y `report` mantienen y vuelven a validar la raíz de extracción existente exacta; en Windows usan un controlador de compartición no eliminable y rechazan puntos de reanálisis. No coloque la contraseña en el comando, entorno, historial de shell ni en una solicitud de soporte. La salida predeterminada del terminal es un resumen conciso y legible; `--json` es una opción explícita de automatización privada y no es la predeterminada.

Para el candidato privado de Windows no publicado, compile e instale el MSIX local según se documenta en la [guía de Windows](docs/windows.md). Nada en ese flujo de trabajo carga o publica el paquete. Sus dependencias directas y transitivas de WinUI se commitan en modo bloqueado; se rechaza una restauración NuGet flotante. La recuperación de iOS cifrado en ese candidato requiere Windows 11 x64 y permanece bloqueada para el estado de listo para lanzamiento hasta que una compilación de Windows sintética, una captura de pantalla y una prueba de humo de extremo a extremo confirmen el flujo nativo.

Linux acepta solo un conjunto conservador de tipos de sistemas de archivos locales ordinarios. Los tipos de sistema de archivos FUSE, de red, compartidos, carpeta compartida de máquina virtual, temporales, de superposición y desconocidos se rechazan sin posibilidad de anulación.

Todas las fuentes de recuperación deben ser controladas por el propietario y locales. Las rutas conocidas de sincronización/compartida en la nube, volúmenes no locales, enlaces simbólicos, puntos de reanálisis de Windows y marcadores de posición hidratados en la nube se rechazan antes de la inspección de la fuente. En Windows, la fuente también debe estar en almacenamiento NTFS local privado para que las verificaciones de identidad de archivos sigan siendo confiables; copie una fuente controlada por el propietario allí antes de la recuperación.

Los comandos de procesamiento central y cifrado de iOS son:

- `recover`: control previo, extracción, análisis e informe en un solo flujo de trabajo
- `extract`: copiar e inventariar solo archivos coincidentes del dominio de la aplicación TV Time
- `analyze`: construir tablas privadas normalizadas a partir de una extracción completa
- `report`: construir informes legibles y visuales a partir de un análisis completo

Los comandos experimentales de Android y exportación oficial son:

- `recover-android-backup`: recuperar un contenedor de copia de seguridad heredada de Android compatible
- `recover-android-snapshot`: recuperar una instantánea de base de datos de Android ya preservada
- `recover-export`: recuperar una exportación oficial de TV Time ZIP o CSV compatible
- `android-probe`: informar sobre la capacidad de copia de seguridad heredada segura para la privacidad
- `android-capture`: capturar explícitamente una copia de seguridad heredada de Android compatible

Ejecute `python -m tvtime_extractor <command> --help` a través del entorno virtual para obtener opciones exactas. `--debug` retiene deliberadamente excepciones en cadena de terceros y puede exponer rutas de copia de seguridad, detalles de dependencias, nombres recuperados o texto de contraseña. Úselo solo en un terminal local privado y nunca pegue ni comparta su rastreo de pila. Las banderas avanzadas `extract --include-decrypted-manifest` y `analyze --include-raw-cache` retienen sustancialmente más datos de cuenta o dispositivo y están desactivadas por defecto. Deliberadamente no están disponibles en el flujo de trabajo `recover` sellado: conserve esas salidas avanzadas para análisis manual privado y use una recuperación predeterminada nueva cuando se requiera validación de finalización nativa.

## Límites y restricciones de extracción

El extractor abre la copia de seguridad completada en modo solo lectura y descifra temporalmente su índice de archivos dentro de la salida privada. Requiere el dominio principal de TV Time `AppDomain-com.tozelabs.tvshowtime` e incluye dominios de complementos de TV Time directamente relacionados. Cada archivo regular seleccionado se copia bajo `TVTime-Extraction/raw/` preservando su dominio y ruta relativa al manifiesto. Los recuentos de archivos, tamaños y hashes se registran de forma privada antes del análisis.

El analizador principal lee el `Documents/DioCache.db` copiado y también reconoce archivos heredados de caché de URL sin extensión compatibles en ese mismo directorio. Esas respuestas antiguas de `NSKeyedArchiver` se decodifican completamente sin conexión; el extractor nunca reproduce sus URLs de solicitud privadas. Una base de datos de caché de imágenes disponible se cataloga como un bonus. Las cachés locales pueden ser incompletas, los eventos pueden sobrevivir sin nombres y TV Time puede cambiar su esquema. Los datos faltantes se declaran en lugar de adivinarse. Retenga la copia de seguridad cifrada original hasta que se validen los títulos, favoritos, episodios, eventos de visualización y marcadores de finalización.

## Lea antes de usar datos reales

- [Guía de macOS](docs/macos.md)
- [Guía de Windows](docs/windows.md)
- [Guía de conversión de serie Refract](docs/refract-import.md)
- [Comprobaciones sintéticas privadas entre plataformas](docs/synthetic-testing.md)
- [Guía de Linux](docs/linux.md)
- [Privacidad y manejo seguro](docs/privacy.md)
- [Referencia de salida](docs/output-reference.md)
- [Solución de problemas](docs/troubleshooting.md)
- [Política de soporte](SUPPORT.md)
- [Política de seguridad](SECURITY.md)

Las pruebas automatizadas usan únicamente datos de prueba inventados. El repositorio nunca debe contener una copia de seguridad real, base de datos, manifiesto de dispositivo, informe recuperado, identificador de cuenta o dispositivo estable, URL privada, contraseña o historial de visualización.

## Licencia

Licenciado bajo la [Licencia MIT](LICENSE). Consulte [CONTRIBUTING.md](CONTRIBUTING.md) y [CHANGELOG.md](CHANGELOG.md). El software se proporciona sin garantía y no es una herramienta de restauración de copias de seguridad. Una aplicación macOS empaquetada también incluye sus textos completos de terceros y un inventario exacto de componentes/licencias bajo `Contents/Resources/Licenses`.

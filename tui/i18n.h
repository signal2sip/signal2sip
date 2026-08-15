// signal2sip-tui: translation catalog + locale detection.
//
// Detects the user's language by reading LC_ALL/LC_MESSAGES/LANG directly
// (POSIX precedence order for message catalogs - LC_ALL overrides every
// category, LC_MESSAGES is message-catalog-specific, LANG is the final
// fallback), rather than going through setlocale()/std::locale: those
// depend on which locales are actually generated on the box (`locale -a`),
// which minimal server installs (e.g. this project's own deploy targets)
// often don't have at all - reading the env var string directly needs
// nothing installed and can't fail. An unset/empty value, or "C"/"POSIX"
// (what a locale-less box or C.UTF-8 both normalize to here, since only
// the part before '_'/'.'/'@' is examined), falls back to English.
//
// Strings are compiled straight into the binary as a table (no .po/.mo
// files, no libintl dependency) to match the rest of this project's
// single-static-binary approach.
//
// Deliberately NOT translated, on purpose:
//   - config field identifiers (server_url, sip_host, sip_srtp, ...) -
//     ConfigFieldDef::label is literally the same string as ::key (see
//     main.cpp), matching gendb's own `config set <field>` names exactly
//     so a value typed here round-trips through the same name gendb
//     expects.
//   - enum values actually sent to signal2sip-gendb as CLI args: Screen
//     4's sip_srtp/sip_transport/sip_tls_insecure cycling values
//     (mandatory/optional/disabled, udp/tls, yes/no) and Screen 5's
//     wizTransport (sms/voice) - these are real argv values, not display
//     text, and must stay exactly what gendb parses.
//   - protocol/brand terms with no real translation in practice (SIP,
//     TLS, SRTP, E.164, ACI, QR, captcha, deactivate/register/link as
//     gendb subcommand names - `unregister` also still works as an
//     alias for `deactivate` on the gendb CLI, but the TUI only ever
//     invokes the new name).
// Everything else - labels, navigation hints, confirmation prose, error/
// warning messages - is translated.
#pragma once

#include <cctype>
#include <cstdlib>
#include <string>

namespace signal2sip::i18n {

enum class Lang { EN, UK, RU, PL, DE, FR, IT, ES, PT };
inline constexpr int kLangCount = 9;

enum class Key {
    ColName, ColType, ColStatus, ColMedia,
    DbReadError, NoAccounts,
    FooterSelect, FooterDetails, FooterNew, FooterRefresh, FooterQuit,
    TypeLinked, TypePrimary,
    StatusEnabled, StatusDisabled, StatusError,
    SrtpMandatory, SrtpOptional,
    DetailLinkedAt, DetailRegisteredAt, DetailEnabled, DetailLastError, DetailLastErrorSince,
    YesWord, NoWord,
    DetailSipNone, DetailSignaling, DetailMedia,
    AccountReadError,
    SectionIdentity, SectionStatus,
    DetailTitlebar, FooterConfigureSip, FooterDisable, FooterEnable, FooterSignalSettings,
    FooterDeleteAccount, FooterBack, FooterReset,
    SignalingUdpInsecure, MediaSrtpNotGuaranteedPrefix,
    ActionEnableTitle, ActionDisableTitle, ActionDeactivateTitle, ActionUnlinkTitle, ActionResetTitle,
    ActionDeleteTitle,
    ActionEnableBody, ActionDisableBody, ActionDeactivateBody, ActionUnlinkBody, ActionDeleteBody,
    ResultDone, ResultError, AnyKeyToList, TypeAccountName, ConfirmAccountLabel,
    FooterCancel, EnterDelete, TypeNameInFull, FooterConfirm,
    ErrSipHostRequired, ErrSipExtensionRequired, ErrSipPasswordRequired, ErrTlsRequiresCa,
    WarnBridgeBothSet,
    ConfigSaved, ConfigSaveError, NoChanges, AnyKeyBackToAccount,
    ConfigTitlebar, FooterField, FooterTextType, FooterListCycles, FooterSave,
    SignalConfigTitlebar, SignalConfigTypeText,
    WizardNewAccount, FieldAccountName, FieldMethod, MethodRegister,
    WizardNameHint, ErrEnterAccountName, ErrAccountExists,
    FooterToggleMethod, FooterNext,
    WizardRegistration, FieldCodeMethod, ErrEnterE164,
    FooterToggleCodeMethod, FooterRegister,
    WizardResult, FooterEnterCode, FooterToList,
    CaptchaInstructions, FieldToken, FooterTypeToken, FooterSubmit,
    WizardVerify, FieldSmsCode, FooterTypeCode,
    WizardLinking, LinkWaitingInstructions, FooterCancelWaiting,
    ResultErrorCancelled,
    WizardTitlebar,
    StartupNoDbConfig,
};
inline constexpr int kKeyCount = static_cast<int>(Key::StartupNoDbConfig) + 1;

namespace detail {

// Row order must match Key's declaration order above; column order must
// match Lang's declaration order (EN, UK, RU, PL, DE, FR, IT, ES, PT).
inline constexpr const char* kTable[kKeyCount][kLangCount] = {
    /* ColName */ {"Name", "Ім'я", "Имя", "Nazwa", "Name", "Nom", "Nome", "Nombre", "Nome"},
    /* ColType */ {"Type", "Тип", "Тип", "Typ", "Typ", "Type", "Tipo", "Tipo", "Tipo"},
    /* ColStatus */ {"Status", "Статус", "Статус", "Status", "Status", "Statut", "Stato", "Estado", "Estado"},
    /* ColMedia */ {"Media", "Медіа", "Медиа", "Media", "Medien", "Média", "Media", "Medios", "Mídia"},
    /* DbReadError */ {"database read error: ", "помилка читання БД: ", "ошибка чтения БД: ",
                        "błąd odczytu bazy danych: ", "Fehler beim Lesen der Datenbank: ",
                        "erreur de lecture de la base de données : ", "errore di lettura del database: ",
                        "error al leer la base de datos: ", "erro ao ler o banco de dados: "},
    /* NoAccounts */ {"(no accounts - signal2sip-gendb <name> register/link)",
                       "(немає акаунтів - signal2sip-gendb <name> register/link)",
                       "(нет аккаунтов - signal2sip-gendb <name> register/link)",
                       "(brak kont - signal2sip-gendb <name> register/link)",
                       "(keine Konten - signal2sip-gendb <name> register/link)",
                       "(aucun compte - signal2sip-gendb <name> register/link)",
                       "(nessun account - signal2sip-gendb <name> register/link)",
                       "(sin cuentas - signal2sip-gendb <name> register/link)",
                       "(nenhuma conta - signal2sip-gendb <name> register/link)"},
    /* FooterSelect */ {"select", "вибір", "выбор", "wybór", "auswählen", "sélection", "seleziona",
                         "seleccionar", "selecionar"},
    /* FooterDetails */ {"details", "деталі", "детали", "szczegóły", "Details", "détails", "dettagli",
                          "detalles", "detalhes"},
    /* FooterNew */ {"new", "новий", "новый", "nowe", "neu", "nouveau", "nuovo", "nuevo", "novo"},
    /* FooterRefresh */ {"refresh", "оновити", "обновить", "odśwież", "aktualisieren", "actualiser", "aggiorna",
                          "actualizar", "atualizar"},
    /* FooterQuit */ {"quit", "вихід", "выход", "wyjście", "beenden", "quitter", "esci", "salir", "sair"},
    /* TypeLinked */ {"linked", "прив'язаний", "привязан", "powiązane", "verknüpft", "lié", "collegato",
                       "vinculado", "vinculado"},
    /* TypePrimary */ {"primary", "основний", "основной", "główne", "primär", "principal", "primario",
                        "principal", "principal"},
    /* StatusEnabled */ {"enabled", "увімкнено", "включён", "włączone", "aktiviert", "activé", "abilitato",
                          "habilitado", "habilitado"},
    /* StatusDisabled */ {"disabled", "вимкнено", "выключен", "wyłączone", "deaktiviert", "désactivé",
                           "disabilitato", "deshabilitado", "desabilitado"},
    /* StatusError */ {"problem", "проблема", "проблема", "problem", "Problem", "problème",
                        "problema", "problema", "problema"},
    /* SrtpMandatory */ {"mandatory", "обов'язково", "обязательно", "wymagane", "erforderlich", "obligatoire",
                          "obbligatorio", "obligatorio", "obrigatório"},
    /* SrtpOptional */ {"optional", "необов'язково", "опционально", "opcjonalne", "optional", "facultatif",
                         "opzionale", "opcional", "opcional"},
    /* DetailLinkedAt */ {"Linked", "Прив'язано", "Привязан", "Powiązano", "Verknüpft", "Lié", "Collegato",
                           "Vinculado", "Vinculado"},
    /* DetailRegisteredAt */ {"Registered", "Зареєстровано", "Зарегистрирован", "Zarejestrowano", "Registriert",
                               "Enregistré", "Registrato", "Registrado", "Registrado"},
    /* DetailEnabled */ {"Enabled", "Увімкнено", "Включён", "Włączone", "Aktiviert", "Activé", "Abilitato",
                          "Habilitado", "Habilitado"},
    /* DetailLastError */ {"Problem", "Проблема", "Проблема", "Problem", "Problem", "Problème",
                            "Problema", "Problema", "Problema"},
    /* DetailLastErrorSince */ {"Since", "З", "С", "Od", "Seit", "Depuis", "Da", "Desde", "Desde"},
    /* YesWord */ {"yes", "так", "да", "tak", "ja", "oui", "sì", "sí", "sim"},
    /* NoWord */ {"no", "ні", "нет", "nie", "nein", "non", "no", "no", "não"},
    /* DetailSipNone */ {"— Signal-only, no SIP", "— лише Signal, без SIP", "— только Signal, без SIP",
                          "— tylko Signal, bez SIP", "— nur Signal, kein SIP", "— Signal uniquement, sans SIP",
                          "— solo Signal, senza SIP", "— solo Signal, sin SIP", "— somente Signal, sem SIP"},
    /* DetailSignaling */ {"Signaling", "Сигналізація", "Сигнализация", "Sygnalizacja", "Signalisierung",
                            "Signalisation", "Segnalazione", "Señalización", "Sinalização"},
    /* DetailMedia */ {"Media (RTP)", "Медіа (RTP)", "Медиа (RTP)", "Media (RTP)", "Medien (RTP)", "Média (RTP)",
                        "Media (RTP)", "Medios (RTP)", "Mídia (RTP)"},
    /* AccountReadError */ {"account read error: ", "помилка читання акаунта: ", "ошибка чтения аккаунта: ",
                             "błąd odczytu konta: ", "Fehler beim Lesen des Kontos: ",
                             "erreur de lecture du compte : ", "errore di lettura dell'account: ",
                             "error al leer la cuenta: ", "erro ao ler a conta: "},
    /* SectionIdentity */ {"IDENTITY", "ІДЕНТИЧНІСТЬ", "ИДЕНТИЧНОСТЬ", "TOŻSAMOŚĆ", "IDENTITÄT", "IDENTITÉ",
                            "IDENTITÀ", "IDENTIDAD", "IDENTIDADE"},
    /* SectionStatus */ {"STATUS (from DB - not live connection)", "СТАТУС (з БД - не поточне з'єднання)",
                          "СТАТУС (из БД - не live-соединение)", "STATUS (z bazy danych - nie na żywo)",
                          "STATUS (aus DB - keine Live-Verbindung)",
                          "STATUT (depuis la BD - pas une connexion en direct)",
                          "STATO (dal DB - non connessione in tempo reale)",
                          "ESTADO (desde la BD - no conexión en vivo)", "STATUS (do BD - não é conexão ao vivo)"},
    /* DetailTitlebar */ {"  Account: ", "  Акаунт: ", "  Аккаунт: ", "  Konto: ", "  Konto: ", "  Compte : ",
                           "  Account: ", "  Cuenta: ", "  Conta: "},
    /* FooterConfigureSip */ {"configure SIP", "налаштувати SIP", "настроить SIP", "konfiguruj SIP",
                               "SIP konfigurieren", "configurer SIP", "configura SIP", "configurar SIP",
                               "configurar SIP"},
    /* FooterDisable */ {"disable", "вимкнути", "выключить", "wyłącz", "deaktivieren", "désactiver", "disabilita",
                          "deshabilitar", "desabilitar"},
    /* FooterEnable */ {"enable", "увімкнути", "включить", "włącz", "aktivieren", "activer", "abilita",
                         "habilitar", "habilitar"},
    /* FooterSignalSettings */ {"Signal settings", "налаштування Signal", "настройки Signal",
                                 "ustawienia Signal", "Signal-Einstellungen", "paramètres Signal",
                                 "impostazioni Signal", "configuración de Signal", "configurações do Signal"},
    /* FooterDeleteAccount */ {"delete account  ", "видалити акаунт  ", "удалить аккаунт  ", "usuń konto  ",
                                "Konto löschen  ", "supprimer le compte  ", "elimina account  ",
                                "eliminar cuenta  ", "excluir conta  "},
    /* FooterBack */ {"back", "назад", "назад", "wstecz", "zurück", "retour", "indietro", "atrás", "voltar"},
    /* FooterReset */ {"reset", "скинути", "сбросить", "zresetuj", "zurücksetzen", "réinitialiser", "resetta",
                        "restablecer", "redefinir"},
    /* SignalingUdpInsecure */ {"⚠ UDP (not encrypted)", "⚠ UDP (не шифровано)", "⚠ UDP (не шифровано)",
                                 "⚠ UDP (nieszyfrowane)", "⚠ UDP (nicht verschlüsselt)", "⚠ UDP (non chiffré)",
                                 "⚠ UDP (non cifrato)", "⚠ UDP (no cifrado)", "⚠ UDP (não criptografado)"},
    /* MediaSrtpNotGuaranteedPrefix */ {"⚠ SRTP not guaranteed ", "⚠ SRTP не гарантовано ", "⚠ SRTP не гарант. ",
                                         "⚠ SRTP niegwarantowane ", "⚠ SRTP nicht garantiert ",
                                         "⚠ SRTP non garanti ", "⚠ SRTP non garantito ",
                                         "⚠ SRTP no garantizado ", "⚠ SRTP não garantido "},
    /* ActionEnableTitle */ {"enable {}?", "увімкнути {}?", "включить {}?", "włączyć {}?", "{} aktivieren?",
                              "activer {} ?", "abilitare {}?", "¿habilitar {}?", "habilitar {}?"},
    /* ActionDisableTitle */ {"disable {}?", "вимкнути {}?", "выключить {}?", "wyłączyć {}?", "{} deaktivieren?",
                               "désactiver {} ?", "disabilitare {}?", "¿deshabilitar {}?", "desabilitar {}?"},
    /* ActionDeactivateTitle */ {"deactivate {}?", "deactivate {}?", "deactivate {}?", "deactivate {}?",
                                  "deactivate {}?", "deactivate {}?", "deactivate {}?", "deactivate {}?",
                                  "deactivate {}?"},
    /* ActionUnlinkTitle */ {"⚠ unlink {}", "⚠ відв'язати {}", "⚠ отвязать {}", "⚠ odłącz {}", "⚠ {} trennen",
                              "⚠ dissocier {}", "⚠ scollega {}", "⚠ desvincular {}", "⚠ desvincular {}"},
    /* ActionResetTitle */ {"⚠ reset {}", "⚠ скинути {}", "⚠ сбросить {}", "⚠ zresetuj {}", "⚠ {} zurücksetzen",
                             "⚠ réinitialiser {}", "⚠ resetta {}", "⚠ restablecer {}", "⚠ redefinir {}"},
    /* ActionDeleteTitle */ {"⚠ delete account {}", "⚠ видалити акаунт {}", "⚠ удалить аккаунт {}",
                              "⚠ usuń konto {}", "⚠ Konto {} löschen", "⚠ supprimer le compte {}",
                              "⚠ elimina l'account {}", "⚠ eliminar la cuenta {}", "⚠ excluir a conta {}"},
    /* ActionEnableBody */
    {"The daemon will bring the Signal session and SIP for this account back up within 30s (or immediately on "
     "SIGHUP).",
     "Демон знову підніме Signal-сесію та SIP для цього акаунта протягом 30с (або одразу по SIGHUP).",
     "Демон снова поднимет Signal-сессию и SIP для этого аккаунта в течение 30с (или сразу по SIGHUP).",
     "Demon ponownie uruchomi sesję Signal i SIP dla tego konta w ciągu 30s (lub natychmiast po SIGHUP).",
     "Der Daemon bringt die Signal-Sitzung und SIP für dieses Konto innerhalb von 30s wieder hoch (oder sofort "
     "bei SIGHUP).",
     "Le démon relancera la session Signal et le SIP pour ce compte dans les 30s (ou immédiatement sur SIGHUP).",
     "Il demone riattiverà la sessione Signal e il SIP per questo account entro 30s (o subito con SIGHUP).",
     "El demonio volverá a levantar la sesión de Signal y el SIP para esta cuenta en 30s (o de inmediato con "
     "SIGHUP).",
     "O daemon vai reerguer a sessão do Signal e o SIP desta conta em até 30s (ou imediatamente com SIGHUP)."},
    /* ActionDisableBody */
    {"The daemon will stop bringing up SIP and the Signal session for this account within 30s (or immediately "
     "on SIGHUP). Incoming calls will stop arriving. Reversible - enable will restore it.",
     "Демон перестане піднімати SIP та Signal-сесію для цього акаунта протягом 30с (або одразу по SIGHUP). "
     "Вхідні дзвінки перестануть надходити. Оборотно - enable поверне як було.",
     "Демон перестанет поднимать SIP и Signal-сессию для этого аккаунта в течение 30с (или сразу по SIGHUP). "
     "Входящие звонки перестанут доходить. Обратимо - enable вернёт как было.",
     "Demon przestanie uruchamiać SIP i sesję Signal dla tego konta w ciągu 30s (lub natychmiast po SIGHUP). "
     "Połączenia przychodzące przestaną docierać. Odwracalne - enable przywróci poprzedni stan.",
     "Der Daemon stellt SIP und die Signal-Sitzung für dieses Konto innerhalb von 30s ein (oder sofort bei "
     "SIGHUP). Eingehende Anrufe kommen nicht mehr an. Reversibel - enable stellt den vorherigen Zustand wieder "
     "her.",
     "Le démon arrêtera le SIP et la session Signal pour ce compte dans les 30s (ou immédiatement sur SIGHUP). "
     "Les appels entrants cesseront d'arriver. Réversible - enable rétablira l'état précédent.",
     "Il demone smetterà di attivare il SIP e la sessione Signal per questo account entro 30s (o subito con "
     "SIGHUP). Le chiamate in arrivo smetteranno di arrivare. Reversibile - enable ripristinerà lo stato "
     "precedente.",
     "El demonio dejará de levantar el SIP y la sesión de Signal para esta cuenta en 30s (o de inmediato con "
     "SIGHUP). Las llamadas entrantes dejarán de llegar. Reversible - enable restaurará el estado anterior.",
     "O daemon vai parar de erguer o SIP e a sessão do Signal desta conta em até 30s (ou imediatamente com "
     "SIGHUP). As chamadas recebidas vão parar de chegar. Reversível - enable restaura o estado anterior."},
    /* ActionDeactivateBody */
    {"A real but reversible server-side flag (fetchesMessages=false) - the number becomes unreachable for "
     "incoming Signal messages until reactivate. Doesn't touch local data.",
     "Реальний, але оборотний серверний прапорець (fetchesMessages=false) - номер стане недоступним для "
     "вхідних Signal-повідомлень до reactivate. Локальні дані не зачіпає.",
     "Реальный, но обратимый серверный флаг (fetchesMessages=false) - номер станет недоступен для входящих "
     "Signal-сообщений до reactivate. Локальные данные не трогает.",
     "Prawdziwa, ale odwracalna flaga po stronie serwera (fetchesMessages=false) - numer stanie się niedostępny "
     "dla przychodzących wiadomości Signal do czasu reactivate. Nie dotyka danych lokalnych.",
     "Ein echtes, aber reversibles serverseitiges Flag (fetchesMessages=false) - die Nummer wird bis zur "
     "Reaktivierung für eingehende Signal-Nachrichten unerreichbar. Lokale Daten bleiben unberührt.",
     "Un indicateur côté serveur réel mais réversible (fetchesMessages=false) - le numéro deviendra injoignable "
     "pour les messages Signal entrants jusqu'à la réactivation. Ne touche pas aux données locales.",
     "Un flag lato server reale ma reversibile (fetchesMessages=false) - il numero diventerà irraggiungibile "
     "per i messaggi Signal in arrivo fino alla riattivazione. Non tocca i dati locali.",
     "Un indicador real pero reversible del lado del servidor (fetchesMessages=false) - el número quedará "
     "inaccesible para los mensajes de Signal entrantes hasta la reactivación. No afecta los datos locales.",
     "Uma flag real, porém reversível, do lado do servidor (fetchesMessages=false) - o número ficará "
     "inacessível para mensagens do Signal recebidas até a reativação. Não afeta os dados locais."},
    /* ActionUnlinkBody */
    {"Irreversible locally: wipes this account's row entirely (keys, sessions, cached contacts, SIP/deployment "
     "config) from the database. LOCAL ONLY - does not contact Signal's servers, so the real account and phone "
     "number are completely unaffected. Re-link or re-register to recreate the local row from scratch.",
     "Незворотно локально: повністю стирає рядок цього акаунта (ключі, сесії, кешовані контакти, "
     "SIP/конфігурацію розгортання) з бази даних. ЛИШЕ ЛОКАЛЬНО - серверів Signal не зачіпає, тож справжній "
     "акаунт і номер телефону абсолютно не постраждають. Щоб відтворити локальний рядок з нуля, знадобиться "
     "повторна прив'язка або реєстрація.",
     "Необратимо локально: полностью стирает строку этого аккаунта (ключи, сессии, кешированные контакты, "
     "SIP/конфигурацию развёртывания) из базы данных. ТОЛЬКО ЛОКАЛЬНО - серверов Signal не затрагивает, поэтому "
     "реальный аккаунт и номер телефона абсолютно не пострадают. Чтобы воссоздать локальную строку с нуля, "
     "понадобится повторная привязка или регистрация.",
     "Nieodwracalne lokalnie: całkowicie usuwa wiersz tego konta (klucze, sesje, zbuforowane kontakty, "
     "konfigurację SIP/wdrożenia) z bazy danych. TYLKO LOKALNIE - nie dotyka serwerów Signal, więc prawdziwe "
     "konto i numer telefonu pozostają całkowicie nienaruszone. Aby odtworzyć lokalny wiersz od zera, potrzebne "
     "będzie ponowne powiązanie lub rejestracja.",
     "Lokal unwiderruflich: löscht den Datensatz dieses Kontos vollständig (Schlüssel, Sitzungen, "
     "zwischengespeicherte Kontakte, SIP-/Bereitstellungskonfiguration) aus der Datenbank. NUR LOKAL - die "
     "Signal-Server werden nicht berührt, das echte Konto und die Telefonnummer bleiben also vollständig "
     "unberührt. Um den lokalen Datensatz neu zu erstellen, ist eine erneute Verknüpfung oder Registrierung "
     "nötig.",
     "Irréversible localement : efface entièrement la ligne de ce compte (clés, sessions, contacts mis en cache, "
     "configuration SIP/déploiement) de la base de données. LOCAL UNIQUEMENT - ne touche pas aux serveurs de "
     "Signal, donc le vrai compte et le numéro de téléphone restent totalement intacts. Il faudra relier ou "
     "réenregistrer pour recréer la ligne locale à partir de zéro.",
     "Irreversibile localmente: cancella completamente la riga di questo account (chiavi, sessioni, contatti in "
     "cache, configurazione SIP/distribuzione) dal database. SOLO LOCALE - non tocca i server di Signal, quindi "
     "l'account reale e il numero di telefono restano del tutto intatti. Per ricreare la riga locale da zero "
     "servirà un nuovo collegamento o una nuova registrazione.",
     "Irreversible localmente: borra por completo la fila de esta cuenta (claves, sesiones, contactos en caché, "
     "configuración SIP/despliegue) de la base de datos. SOLO LOCAL - no afecta a los servidores de Signal, por "
     "lo que la cuenta real y el número de teléfono quedan completamente intactos. Para recrear la fila local "
     "desde cero hará falta volver a vincular o registrar.",
     "Irreversível localmente: apaga por completo a linha desta conta (chaves, sessões, contatos em cache, "
     "configuração SIP/implantação) do banco de dados. APENAS LOCAL - não afeta os servidores do Signal, então "
     "a conta real e o número de telefone ficam totalmente intactos. Para recriar a linha local do zero será "
     "preciso vincular ou registrar novamente."},
    /* ActionDeleteBody */
    {"Irreversible. A real DELETE /v1/accounts/me on the Signal server - the number is freed up for someone "
     "else to register, local keys are wiped on success.",
     "Незворотно. Реальний DELETE /v1/accounts/me на сервері Signal - номер звільняється для чужої реєстрації, "
     "локальні ключі стираються при успіху.",
     "Необратимо. Реальный DELETE /v1/accounts/me на сервере Signal - номер освобождается для чужой "
     "регистрации, локальные ключи стираются при успехе.",
     "Nieodwracalne. Prawdziwe DELETE /v1/accounts/me na serwerze Signal - numer zostaje zwolniony do "
     "rejestracji przez kogoś innego, lokalne klucze są usuwane po powodzeniu.",
     "Unwiderruflich. Ein echtes DELETE /v1/accounts/me auf dem Signal-Server - die Nummer wird für die "
     "Registrierung durch jemand anderen freigegeben, lokale Schlüssel werden bei Erfolg gelöscht.",
     "Irréversible. Un vrai DELETE /v1/accounts/me sur le serveur Signal - le numéro est libéré pour "
     "l'enregistrement par quelqu'un d'autre, les clés locales sont effacées en cas de succès.",
     "Irreversibile. Una vera DELETE /v1/accounts/me sul server Signal - il numero viene liberato per la "
     "registrazione da parte di qualcun altro, le chiavi locali vengono cancellate in caso di successo.",
     "Irreversible. Un DELETE /v1/accounts/me real en el servidor de Signal - el número queda liberado para "
     "que otra persona lo registre, las claves locales se borran si tiene éxito.",
     "Irreversível. Um DELETE /v1/accounts/me real no servidor do Signal - o número é liberado para que outra "
     "pessoa o registre, as chaves locais são apagadas em caso de sucesso."},
    /* ResultDone */ {"done", "виконано", "выполнено", "wykonano", "erledigt", "terminé", "eseguito", "hecho",
                       "concluído"},
    /* ResultError */ {"error (code {})", "помилка (код {})", "ошибка (код {})", "błąd (kod {})",
                        "Fehler (Code {})", "erreur (code {})", "errore (codice {})", "error (código {})",
                        "erro (código {})"},
    /* AnyKeyToList */ {"any key - back to list", "будь-яка клавіша - до списку", "любая клавиша - к списку",
                         "dowolny klawisz - wróć do listy", "beliebige Taste - zurück zur Liste",
                         "n'importe quelle touche - retour à la liste", "qualsiasi tasto - torna alla lista",
                         "cualquier tecla - volver a la lista", "qualquer tecla - voltar à lista"},
    /* TypeAccountName */ {"type account name: ", "введіть ім'я акаунта: ", "введите имя аккаунта: ",
                            "wpisz nazwę konta: ", "Kontoname eingeben: ", "saisissez le nom du compte : ",
                            "digita il nome dell'account: ", "escriba el nombre de la cuenta: ",
                            "digite o nome da conta: "},
    /* ConfirmAccountLabel */ {"Account: ", "Акаунт: ", "Аккаунт: ", "Konto: ", "Konto: ", "Compte : ",
                                "Account: ", "Cuenta: ", "Conta: "},
    /* FooterCancel */ {"cancel", "скасувати", "отмена", "anuluj", "abbrechen", "annuler", "annulla", "cancelar",
                         "cancelar"},
    /* EnterDelete */ {"delete", "видалити", "удалить", "usuń", "löschen", "supprimer", "elimina", "eliminar",
                        "excluir"},
    /* TypeNameInFull */ {"(type the full name)", "(введіть ім'я повністю)", "(наберите имя полностью)",
                           "(wpisz pełną nazwę)", "(vollständigen Namen eingeben)",
                           "(saisissez le nom complet)", "(digita il nome completo)",
                           "(escriba el nombre completo)", "(digite o nome completo)"},
    /* FooterConfirm */ {"confirm", "підтвердити", "подтвердить", "potwierdź", "bestätigen", "confirmer",
                          "conferma", "confirmar", "confirmar"},
    /* ErrSipHostRequired */
    {"sip_host is required once SIP is being configured", "sip_host обов'язковий, якщо налаштовується SIP",
     "sip_host обязателен, раз настраивается SIP", "sip_host jest wymagane, skoro konfigurowane jest SIP",
     "sip_host ist erforderlich, sobald SIP konfiguriert wird",
     "sip_host est requis dès lors que le SIP est configuré", "sip_host è obbligatorio se si configura il SIP",
     "sip_host es obligatorio si se está configurando SIP",
     "sip_host é obrigatório quando o SIP está sendo configurado"},
    /* ErrSipExtensionRequired */
    {"sip_extension is required once SIP is being configured",
     "sip_extension обов'язковий, якщо налаштовується SIP", "sip_extension обязателен, раз настраивается SIP",
     "sip_extension jest wymagane, skoro konfigurowane jest SIP",
     "sip_extension ist erforderlich, sobald SIP konfiguriert wird",
     "sip_extension est requis dès lors que le SIP est configuré",
     "sip_extension è obbligatorio se si configura il SIP",
     "sip_extension es obligatorio si se está configurando SIP",
     "sip_extension é obrigatório quando o SIP está sendo configurado"},
    /* ErrSipPasswordRequired */
    {"sip_password is required once SIP is being configured",
     "sip_password обов'язковий, якщо налаштовується SIP", "sip_password обязателен, раз настраивается SIP",
     "sip_password jest wymagane, skoro konfigurowane jest SIP",
     "sip_password ist erforderlich, sobald SIP konfiguriert wird",
     "sip_password est requis dès lors que le SIP est configuré",
     "sip_password è obbligatorio se si configura il SIP",
     "sip_password es obligatorio si se está configurando SIP",
     "sip_password é obrigatório quando o SIP está sendo configurado"},
    /* ErrTlsRequiresCa */
    {"sip_transport=tls requires sip_tls_ca_file or sip_tls_insecure=yes",
     "sip_transport=tls потребує sip_tls_ca_file або sip_tls_insecure=yes",
     "sip_transport=tls требует sip_tls_ca_file или sip_tls_insecure=yes",
     "sip_transport=tls wymaga sip_tls_ca_file lub sip_tls_insecure=yes",
     "sip_transport=tls erfordert sip_tls_ca_file oder sip_tls_insecure=yes",
     "sip_transport=tls nécessite sip_tls_ca_file ou sip_tls_insecure=yes",
     "sip_transport=tls richiede sip_tls_ca_file o sip_tls_insecure=yes",
     "sip_transport=tls requiere sip_tls_ca_file o sip_tls_insecure=yes",
     "sip_transport=tls requer sip_tls_ca_file ou sip_tls_insecure=yes"},
    /* WarnBridgeBothSet */
    {"both sip_bridge_destination and sip_bridge_did are set - only sip_bridge_did will apply",
     "задані і sip_bridge_destination, і sip_bridge_did - застосується лише sip_bridge_did",
     "заданы и sip_bridge_destination, и sip_bridge_did - применится только sip_bridge_did",
     "ustawione są zarówno sip_bridge_destination, jak i sip_bridge_did - zastosowane zostanie tylko "
     "sip_bridge_did",
     "sowohl sip_bridge_destination als auch sip_bridge_did sind gesetzt - nur sip_bridge_did wird angewendet",
     "sip_bridge_destination et sip_bridge_did sont tous deux définis - seul sip_bridge_did sera appliqué",
     "sono impostati sia sip_bridge_destination che sip_bridge_did - verrà applicato solo sip_bridge_did",
     "están definidos tanto sip_bridge_destination como sip_bridge_did - solo se aplicará sip_bridge_did",
     "tanto sip_bridge_destination quanto sip_bridge_did estão definidos - apenas sip_bridge_did será aplicado"},
    /* ConfigSaved */ {"saved", "збережено", "сохранено", "zapisano", "gespeichert", "enregistré", "salvato",
                        "guardado", "salvo"},
    /* ConfigSaveError */ {"save error", "помилка збереження", "ошибка сохранения", "błąd zapisu",
                            "Fehler beim Speichern", "erreur d'enregistrement", "errore di salvataggio",
                            "error al guardar", "erro ao salvar"},
    /* NoChanges */ {"(no changes)", "(без змін)", "(изменений нет)", "(brak zmian)", "(keine Änderungen)",
                      "(aucun changement)", "(nessuna modifica)", "(sin cambios)", "(sem alterações)"},
    /* AnyKeyBackToAccount */ {"any key - back to account", "будь-яка клавіша - назад до акаунта",
                                "любая клавиша - назад к аккаунту", "dowolny klawisz - wróć do konta",
                                "beliebige Taste - zurück zum Konto",
                                "n'importe quelle touche - retour au compte", "qualsiasi tasto - torna "
                                                                               "all'account",
                                "cualquier tecla - volver a la cuenta", "qualquer tecla - voltar à conta"},
    /* ConfigTitlebar */ {"  SIP configuration: ", "  Налаштування SIP: ", "  Настройка SIP: ",
                           "  Konfiguracja SIP: ", "  SIP-Konfiguration: ", "  Configuration SIP : ",
                           "  Configurazione SIP: ", "  Configuración SIP: ", "  Configuração SIP: "},
    /* FooterField */ {"field", "поле", "поле", "pole", "Feld", "champ", "campo", "campo", "campo"},
    /* FooterTextType */ {"text: type  ", "текст: вводьте  ", "текст: вводите  ", "tekst: wpisz  ",
                           "Text: eingeben  ", "texte : saisissez  ", "testo: digita  ", "texto: escriba  ",
                           "texto: digite  "},
    /* FooterListCycles */ {"list: cycles", "список: перемикає", "список: переключает", "lista: przełącza",
                             "Liste: wechselt", "liste : change", "elenco: cambia", "lista: cambia",
                             "lista: alterna"},
    /* FooterSave */ {"save", "зберегти", "сохранить", "zapisz", "speichern", "enregistrer", "salva", "guardar",
                       "salvar"},
    /* SignalConfigTitlebar */ {"  Signal settings: ", "  Налаштування Signal: ", "  Настройки Signal: ",
                                 "  Ustawienia Signal: ", "  Signal-Einstellungen: ", "  Paramètres Signal : ",
                                 "  Impostazioni Signal: ", "  Configuración de Signal: ",
                                 "  Configurações do Signal: "},
    /* SignalConfigTypeText */ {" type text  ", " вводьте текст  ", " вводите текст  ", " wpisz tekst  ",
                                 " Text eingeben  ", " saisissez le texte  ", " digita il testo  ",
                                 " escriba el texto  ", " digite o texto  "},
    /* WizardNewAccount */ {"new account", "новий акаунт", "новый аккаунт", "nowe konto", "neues Konto",
                             "nouveau compte", "nuovo account", "nueva cuenta", "nova conta"},
    /* FieldAccountName */ {"account name", "ім'я акаунта", "имя аккаунта", "nazwa konta", "Kontoname",
                             "nom du compte", "nome account", "nombre de la cuenta", "nome da conta"},
    /* FieldMethod */ {"method", "спосіб", "способ", "metoda", "Methode", "méthode", "metodo", "método",
                        "método"},
    /* MethodRegister */ {"register (SMS/call)", "register (SMS/дзвінок)", "register (SMS/звонок)",
                           "register (SMS/połączenie)", "register (SMS/Anruf)", "register (SMS/appel)",
                           "register (SMS/chiamata)", "register (SMS/llamada)", "register (SMS/chamada)"},
    /* WizardNameHint */
    {"name is an arbitrary label (letters/digits/-/_), Signal/SIP never see it",
     "ім'я - довільна мітка (літери/цифри/-/_), Signal/SIP її не бачать",
     "имя - произвольная метка (буквы/цифры/-/_), Signal/SIP её не видят",
     "nazwa to dowolna etykieta (litery/cyfry/-/_), Signal/SIP jej nie widzą",
     "der Name ist ein frei wählbares Label (Buchstaben/Zahlen/-/_), Signal/SIP sehen ihn nie",
     "le nom est une étiquette libre (lettres/chiffres/-/_), Signal/SIP ne le voient jamais",
     "il nome è un'etichetta arbitraria (lettere/numeri/-/_), Signal/SIP non lo vedono mai",
     "el nombre es una etiqueta arbitraria (letras/dígitos/-/_), Signal/SIP nunca lo ven",
     "o nome é um rótulo arbitrário (letras/dígitos/-/_), Signal/SIP nunca o veem"},
    /* ErrEnterAccountName */ {"enter an account name", "вкажіть ім'я акаунта", "укажите имя аккаунта",
                                "podaj nazwę konta", "Kontoname eingeben", "indiquez un nom de compte",
                                "inserisci un nome account", "indique un nombre de cuenta",
                                "informe um nome de conta"},
    /* ErrAccountExists */
    {"an account with this name already exists", "акаунт з таким ім'ям вже існує",
     "аккаунт с таким именем уже существует", "konto o tej nazwie już istnieje",
     "ein Konto mit diesem Namen existiert bereits", "un compte portant ce nom existe déjà",
     "esiste già un account con questo nome", "ya existe una cuenta con ese nombre",
     "já existe uma conta com esse nome"},
    /* FooterToggleMethod */ {"toggle method", "перемкнути спосіб", "переключить способ", "przełącz metodę",
                               "Methode wechseln", "changer de méthode", "cambia metodo", "cambiar método",
                               "alternar método"},
    /* FooterNext */ {"next", "далі", "далее", "dalej", "weiter", "suivant", "avanti", "siguiente", "próximo"},
    /* WizardRegistration */ {"registration: ", "реєстрація: ", "регистрация: ", "rejestracja: ",
                               "Registrierung: ", "inscription : ", "registrazione: ", "registro: ",
                               "registro: "},
    /* FieldCodeMethod */ {"code method", "спосіб коду", "способ кода", "metoda kodu", "Code-Methode",
                            "méthode du code", "metodo del codice", "método del código", "método do código"},
    /* ErrEnterE164 */ {"enter e164", "вкажіть e164", "укажите e164", "podaj e164", "e164 eingeben",
                         "indiquez le e164", "inserisci e164", "indique el e164", "informe o e164"},
    /* FooterToggleCodeMethod */ {"toggle code method", "перемкнути спосіб коду", "переключить способ кода",
                                   "przełącz metodę kodu", "Code-Methode wechseln", "changer la méthode du code",
                                   "cambia metodo del codice", "cambiar método del código",
                                   "alternar método do código"},
    /* FooterRegister */ {"register", "register", "register", "register", "register", "register", "register",
                           "register", "register"},
    /* WizardResult */ {"result: ", "результат: ", "результат: ", "wynik: ", "Ergebnis: ", "résultat : ",
                         "risultato: ", "resultado: ", "resultado: "},
    /* FooterEnterCode */ {"enter code", "ввести код", "ввести код", "wpisz kod", "Code eingeben",
                            "saisir le code", "inserisci codice", "ingresar código", "inserir código"},
    /* FooterToList */ {"to list", "до списку", "к списку", "do listy", "zur Liste", "vers la liste",
                         "alla lista", "a la lista", "para a lista"},
    /* CaptchaInstructions */
    {"Open in a browser: https://signalcaptchas.org/registration/generate.html - solve the captcha; it will "
     "try to navigate to signalcaptcha://<token> (the navigation won't work in a normal browser, but the token "
     "stays visible in the address bar).",
     "Відкрийте в браузері: https://signalcaptchas.org/registration/generate.html - розв'яжіть капчу; вона "
     "спробує перейти на signalcaptcha://<token> (перехід не спрацює у звичайному браузері, але токен "
     "залишиться видимим в адресному рядку).",
     "Откройте в браузере: https://signalcaptchas.org/registration/generate.html - решите капчу; она попробует "
     "перейти на signalcaptcha://<token> (переход не сработает в обычном браузере, но токен останется виден в "
     "адресной строке).",
     "Otwórz w przeglądarce: https://signalcaptchas.org/registration/generate.html - rozwiąż captchę; spróbuje "
     "ona przejść do signalcaptcha://<token> (przejście nie zadziała w zwykłej przeglądarce, ale token "
     "pozostanie widoczny w pasku adresu).",
     "Im Browser öffnen: https://signalcaptchas.org/registration/generate.html - Captcha lösen; es versucht, "
     "zu signalcaptcha://<token> zu navigieren (funktioniert in einem normalen Browser nicht, aber das Token "
     "bleibt in der Adressleiste sichtbar).",
     "Ouvrez dans un navigateur : https://signalcaptchas.org/registration/generate.html - résolvez le captcha "
     "; il essaiera de naviguer vers signalcaptcha://<token> (la navigation ne fonctionnera pas dans un "
     "navigateur normal, mais le jeton restera visible dans la barre d'adresse).",
     "Apri nel browser: https://signalcaptchas.org/registration/generate.html - risolvi il captcha; proverà a "
     "passare a signalcaptcha://<token> (la navigazione non funzionerà in un browser normale, ma il token "
     "rimarrà visibile nella barra degli indirizzi).",
     "Abra en un navegador: https://signalcaptchas.org/registration/generate.html - resuelva el captcha; "
     "intentará navegar a signalcaptcha://<token> (la navegación no funcionará en un navegador normal, pero el "
     "token seguirá visible en la barra de direcciones).",
     "Abra no navegador: https://signalcaptchas.org/registration/generate.html - resolva o captcha; ele "
     "tentará navegar para signalcaptcha://<token> (a navegação não vai funcionar em um navegador normal, mas "
     "o token continuará visível na barra de endereço)."},
    /* FieldToken */ {"token", "токен", "токен", "token", "Token", "jeton", "token", "token", "token"},
    /* FooterTypeToken */ {" type the token  ", " вводьте токен  ", " вводите токен  ", " wpisz token  ",
                            " Token eingeben  ", " saisissez le jeton  ", " digita il token  ",
                            " escriba el token  ", " digite o token  "},
    /* FooterSubmit */ {"submit", "надіслати", "отправить", "wyślij", "senden", "envoyer", "invia", "enviar",
                         "enviar"},
    /* WizardVerify */ {"verification code: ", "код підтвердження: ", "код подтверждения: ",
                         "kod weryfikacyjny: ", "Bestätigungscode: ", "code de vérification : ",
                         "codice di verifica: ", "código de verificación: ", "código de verificação: "},
    /* FieldSmsCode */ {"code from SMS/call", "код з SMS/дзвінка", "код из SMS/звонка", "kod z SMS/połączenia",
                         "Code aus SMS/Anruf", "code reçu par SMS/appel", "codice da SMS/chiamata",
                         "código de SMS/llamada", "código do SMS/chamada"},
    /* FooterTypeCode */ {" type the code  ", " вводьте код  ", " вводите код  ", " wpisz kod  ",
                           " Code eingeben  ", " saisissez le code  ", " digita il codice  ",
                           " escriba el código  ", " digite o código  "},
    /* WizardLinking */ {"linking: ", "лінкування: ", "линковка: ", "łączenie: ", "Verknüpfung: ", "liaison : ",
                          "collegamento: ", "vinculación: ", "vinculação: "},
    /* LinkWaitingInstructions */
    {"Waiting for the QR to be scanned (up to ~90s) - on the phone's Signal: Settings → Linked Devices → Link "
     "New Device",
     "Очікування сканування QR (до ~90с) - Signal на телефоні: Налаштування → Пов'язані пристрої → Пов'язати "
     "пристрій",
     "Ожидание сканирования QR (до ~90с) - Signal на телефоне: Настройки → Связанные устройства → Связать "
     "устройство",
     "Oczekiwanie na zeskanowanie kodu QR (do ~90s) - Signal na telefonie: Ustawienia → Połączone urządzenia → "
     "Połącz urządzenie",
     "Warten auf das Scannen des QR-Codes (bis zu ~90s) - Signal auf dem Telefon: Einstellungen → Verknüpfte "
     "Geräte → Gerät verknüpfen",
     "En attente du scan du QR (jusqu'à ~90s) - Signal sur le téléphone : Paramètres → Appareils liés → Lier "
     "un appareil",
     "In attesa della scansione del QR (fino a ~90s) - Signal sul telefono: Impostazioni → Dispositivi "
     "collegati → Collega dispositivo",
     "Esperando a que se escanee el QR (hasta ~90s) - Signal en el teléfono: Configuración → Dispositivos "
     "vinculados → Vincular nuevo dispositivo",
     "Aguardando a leitura do QR (até ~90s) - Signal no telefone: Configurações → Dispositivos vinculados → "
     "Vincular novo dispositivo"},
    /* FooterCancelWaiting */ {"cancel waiting", "скасувати очікування", "отменить ожидание",
                                "anuluj oczekiwanie", "Warten abbrechen", "annuler l'attente", "annulla attesa",
                                "cancelar espera", "cancelar espera"},
    /* ResultErrorCancelled */ {"error/cancelled (code {})", "помилка/скасовано (код {})",
                                 "ошибка/отменено (код {})", "błąd/anulowano (kod {})",
                                 "Fehler/abgebrochen (Code {})", "erreur/annulé (code {})",
                                 "errore/annullato (codice {})", "error/cancelado (código {})",
                                 "erro/cancelado (código {})"},
    /* WizardTitlebar */ {"  New account: ", "  Новий акаунт: ", "  Новый аккаунт: ", "  Nowe konto: ",
                           "  Neues Konto: ", "  Nouveau compte : ", "  Nuovo account: ", "  Nueva cuenta: ",
                           "  Nova conta: "},
    /* StartupNoDbConfig */
    {" has no usable [global] db_path/db_key - run signal2sip-gendb once first (it bootstraps [global] on a "
     "clean setup).\n",
     " не має придатних [global] db_path/db_key - спочатку один раз запустіть signal2sip-gendb (він ініціалізує "
     "[global] на чистій установці).\n",
     " не содержит пригодных [global] db_path/db_key - сначала один раз запустите signal2sip-gendb (он "
     "инициализирует [global] на чистой установке).\n",
     " nie zawiera użytecznych [global] db_path/db_key - najpierw uruchom raz signal2sip-gendb (inicjuje "
     "[global] przy czystej instalacji).\n",
     " enthält kein nutzbares [global] db_path/db_key - führen Sie zuerst einmal signal2sip-gendb aus (es "
     "initialisiert [global] bei einer sauberen Installation).\n",
     " ne contient pas de [global] db_path/db_key utilisable - lancez d'abord signal2sip-gendb une fois (il "
     "initialise [global] sur une installation vierge).\n",
     " non contiene un [global] db_path/db_key utilizzabile - esegui prima signal2sip-gendb una volta "
     "(inizializza [global] su un'installazione pulita).\n",
     " no tiene un [global] db_path/db_key utilizable - ejecute primero signal2sip-gendb una vez (inicializa "
     "[global] en una instalación limpia).\n",
     " não tem um [global] db_path/db_key utilizável - execute o signal2sip-gendb uma vez primeiro (ele "
     "inicializa o [global] numa instalação limpa).\n"},
};

} // namespace detail

inline Lang detectLang() {
    const char* vars[] = {std::getenv("LC_ALL"), std::getenv("LC_MESSAGES"), std::getenv("LANG")};
    for (const char* v : vars) {
        if (!v || !*v) continue;
        std::string code;
        for (int i = 0; v[i] && v[i] != '_' && v[i] != '.' && v[i] != '@'; i++) {
            code += static_cast<char>(std::tolower(static_cast<unsigned char>(v[i])));
        }
        if (code == "en") return Lang::EN;
        if (code == "uk") return Lang::UK;
        if (code == "ru") return Lang::RU;
        if (code == "pl") return Lang::PL;
        if (code == "de") return Lang::DE;
        if (code == "fr") return Lang::FR;
        if (code == "it") return Lang::IT;
        if (code == "es") return Lang::ES;
        if (code == "pt") return Lang::PT;
        if (code == "c" || code == "posix") return Lang::EN;
        // Anything else recognized-but-unsupported (e.g. "ja", "zh") falls
        // through to the next var, then to the EN default below - not an
        // immediate return, so LC_MESSAGES/LANG still get a chance if
        // LC_ALL names a language we don't have strings for.
    }
    return Lang::EN;
}

inline Lang& currentLang() {
    static Lang lang = detectLang();
    return lang;
}

inline const char* tr(Key k) { return detail::kTable[static_cast<int>(k)][static_cast<int>(currentLang())]; }

// Replaces the first "{}" in tr(k) with arg - used for the handful of
// strings that embed a runtime value (account name, error code) where
// word order legitimately varies by language (e.g. German verb-final
// placement in ActionEnableTitle/ActionDisableTitle).
inline std::string format1(Key k, const std::string& arg) {
    std::string s = tr(k);
    size_t pos = s.find("{}");
    if (pos != std::string::npos) s.replace(pos, 2, arg);
    return s;
}

inline std::string format1(Key k, int arg) { return format1(k, std::to_string(arg)); }

} // namespace signal2sip::i18n

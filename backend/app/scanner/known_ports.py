"""Extra TCP ports to include in standard scans (candidates only).

These are documented *default* listen ports for common local / self-hosted
AI and LLM stacks, web-app dev servers, and TrueNAS SCALE Apps catalog host
ports. They exist so nmap --top-ports does not miss them.

Ports are NOT identity: an open port here only means "worth scanning / probing".
Service names (Ollama, LM Studio, …) must come from response fingerprints
(title, body, JSON shape, Server header) in web capture - see
``app.core.web_capture.identify_ai``.

TrueNAS Apps catalog ports (``TRUENAS_APPS_TCP_PORTS``) are *not* merged into
``STANDARD_EXTRA_TCP_PORTS``; they are scanned only on hosts identified as
TrueNAS (see ``app.scanner.identify_truenas``).
"""
from __future__ import annotations

from ..netutils import PortScope

# Documented defaults for local LLM APIs / UIs that often fall outside --top-ports.
# Keep comments tied to the usual product; do not treat the comment as proof at runtime.
AI_LLM_TCP_PORTS: tuple[int, ...] = (
    1234,   # LM Studio local server (lms server start --port 1234)
    1337,   # Jan desktop API
    2242,   # Aphrodite Engine
    3001,   # AnythingLLM (Docker -p 3001:3001)
    4000,   # LiteLLM proxy
    4891,   # GPT4All local API
    5001,   # KoboldCPP
    7860,   # Gradio (many local AI UIs, including text-generation-webui)
    9997,   # Xinference (xinference-local --port 9997)
    10000,  # Msty local server
    11434,  # Ollama (ollama serve)
    30000,  # SGLang
)

# Default listen ports of modern web-app dev servers and frameworks - the ones AI code
# assistants scaffold onto by default. Open here means "likely HTTP, worth scanning / probing",
# never a product label.
WEB_DEV_TCP_PORTS: tuple[int, ...] = (
    3000,   # Node / Next.js / Create React App / Rails / Grafana
    3030,   # Meteor
    3050,   # dev tooling / RethinkDB admin / Firebird
    4000,   # Phoenix / Jekyll (also LiteLLM, above)
    4200,   # Angular CLI
    4321,   # Astro
    5000,   # Flask / ASP.NET Core / Docker registry
    5173,   # Vite
    5174,   # Vite (second instance)
    5500,   # VS Code Live Server
    8000,   # Django / uvicorn / python -m http.server / FastAPI
    8080,   # common HTTP alternate / many proxied dev servers
    8081,   # common HTTP alternate
    8443,   # common HTTPS alternate
    8501,   # Streamlit
    8888,   # Jupyter
    9000,   # SonarQube / PHP-FPM / various dashboards
)

# TrueNAS SCALE Apps catalog default *host* ports from truenas/apps questions.yaml
# (ix-dev/*/questions.yaml port_number defaults). Scanned only on TrueNAS-identified hosts.
TRUENAS_APPS_TCP_PORTS: tuple[int, ...] = (
    30000,  # ebbwell
    30001,  # solidping
    30002,  # yuvomi
    30003,  # elastic-search
    30004,  # adguard-home
    30005,  # clamav
    30006,  # clamav
    30007,  # ddns-updater
    30008,  # gitea
    30009,  # gitea
    30010,  # ipfs
    30011,  # ipfs
    30012,  # ipfs
    30013,  # jellyfin
    30014,  # jellyfin
    30015,  # glances
    30016,  # autobrr
    30017,  # jenkins
    30018,  # mumble
    30019,  # mumble
    30020,  # nginx-proxy-manager
    30021,  # nginx-proxy-manager
    30022,  # nginx-proxy-manager
    30023,  # unifi-controller
    30024,  # qbittorrent
    30025,  # radarr
    30026,  # rsyncd
    30027,  # nextcloud
    30028,  # firefly-iii
    30029,  # tdarr
    30030,  # terraria
    30031,  # tftpd-hpa
    30032,  # vaultwarden
    30033,  # teamspeak
    30034,  # planka
    30035,  # webdav
    30036,  # webdav
    30037,  # grafana
    30038,  # deluge
    30039,  # deluge
    30040,  # wordpress
    30041,  # immich
    30042,  # storyteller
    30043,  # navidrome
    30044,  # handbrake
    30045,  # next-explorer
    30046,  # bazarr
    30047,  # tautulli
    30048,  # komga
    30049,  # node-red
    30050,  # prowlarr
    30051,  # filebrowser
    30052,  # mineos
    30053,  # searxng
    30054,  # homepage
    30055,  # sabnzbd
    30056,  # pgadmin
    30057,  # wg-easy
    30058,  # wg-easy
    30059,  # redis
    30060,  # umami
    30061,  # romm
    30062,  # odoo
    30063,  # it-tools
    30064,  # dozzle
    30065,  # zigbee2mqtt
    30066,  # piwigo
    30067,  # audiobookshelf
    30068,  # ollama
    30069,  # kavita
    30070,  # paperless-ngx
    30071,  # lidarr
    30072,  # unifi-controller
    30073,  # unifi-controller
    30074,  # unifi-controller
    30075,  # unifi-controller
    30076,  # omada-controller
    30077,  # omada-controller
    30078,  # omada-controller
    30079,  # omada-controller
    30080,  # briefkasten
    30081,  # twofactor-auth
    30082,  # flame
    30083,  # linkding
    30084,  # fscrawler
    30085,  # castopod
    30086,  # logseq
    30087,  # listmonk
    30088,  # tdarr
    30089,  # handbrake
    30090,  # drawio
    30091,  # drawio
    30092,  # homer
    30093,  # kapowarr
    30094,  # metube
    30095,  # distribution
    30096,  # transmission
    30097,  # passbolt
    30098,  # flaresolverr
    30099,  # pigallery2
    30100,  # homarr
    30101,  # tiny-media-manager
    30102,  # diskoverdata
    30103,  # home-assistant
    30104,  # prometheus
    30105,  # firefly-iii
    30106,  # joplin
    30107,  # vikunja
    30108,  # freshrss
    30109,  # n8n
    30110,  # whoogle
    30111,  # mealie
    30112,  # sftpgo
    30113,  # sonarr
    30114,  # octoprint
    30115,  # influxdb
    30116,  # open-speed-test
    30117,  # open-speed-test
    30118,  # jackett
    30119,  # heimdall
    30120,  # heimdall
    30121,  # duplicati
    30122,  # kerberos-agent
    30123,  # unmanic
    30124,  # stirling-pdf
    30125,  # nextcloud
    30126,  # sftpgo
    30127,  # flood
    30128,  # kasm-workspaces
    30129,  # kasm-workspaces
    30130,  # scrypted
    30131,  # scrypted
    30132,  # pihole
    30133,  # authelia
    30134,  # onlyoffice-document-server
    30135,  # monitee-agent
    30136,  # monitee-agent
    30137,  # cockpit-ws
    30138,  # mitmproxy
    30139,  # mitmproxy
    30140,  # authentik
    30141,  # authentik
    30142,  # forgejo
    30143,  # forgejo
    30144,  # outline
    30145,  # code-server
    30146,  # crafty-4
    30147,  # karakeep
    30148,  # warracker
    30149,  # homebox
    30150,  # playwright
    30151,  # spottarr
    30152,  # concourse
    30153,  # concourse
    30154,  # convertx
    30155,  # windmill
    30156,  # windmill
    30157,  # versitygw
    30158,  # versitygw
    30159,  # change-detection
    30160,  # komodo
    30161,  # dawarich
    30162,  # pterodactyl-panel
    30163,  # baserow
    30164,  # zipline
    30165,  # notifiarr
    30166,  # woodpecker-ci
    30167,  # woodpecker-ci
    30168,  # woodpecker-ci
    30169,  # affine
    30170,  # wger
    30171,  # lancache-monolithic
    30172,  # lancache-monolithic
    30173,  # automatic-ripping-machine
    30174,  # directus
    30175,  # fireshare
    30176,  # jellystat
    30177,  # bitmagnet
    30178,  # bitmagnet
    30179,  # gramps-web
    30180,  # maintainerr
    30181,  # tvheadend
    30182,  # tvheadend
    30183,  # nocodb
    30184,  # ntfy
    30185,  # ntfy
    30186,  # garage
    30187,  # garage
    30188,  # garage
    30189,  # garage
    30190,  # garage
    30191,  # zwave-js-ui
    30192,  # zwave-js-ui
    30193,  # frigate
    30194,  # frigate
    30195,  # frigate
    30196,  # frigate
    30197,  # frigate
    30198,  # stash
    30199,  # sickgear
    30200,  # seaweedfs
    30201,  # seaweedfs
    30202,  # seaweedfs
    30203,  # seaweedfs
    30204,  # seaweedfs
    30205,  # luanti
    30206,  # traccar
    30207,  # pairdrop
    30208,  # chatwoot
    30209,  # memcached
    30210,  # headscale
    30211,  # kitchenowl
    30212,  # minio-console
    30213,  # minio-console
    30214,  # bookstack
    30215,  # gotify
    30216,  # gotify
    30217,  # requestrr
    30218,  # pocket-id
    30219,  # grocy
    30220,  # speedtest-tracker
    30221,  # speedtest-tracker
    30222,  # shoko-server
    30223,  # profilarr
    30224,  # peanut
    30225,  # cloudbeaver
    30226,  # paperless-ai
    30227,  # shlink
    30228,  # omni-tools
    30229,  # wizarr
    30230,  # byparr
    30231,  # photoview
    30232,  # enclosed
    30233,  # portracker
    30234,  # makemkv
    30235,  # many-notes
    30236,  # kiwix-server
    30237,  # kimai
    30238,  # keycloak
    30239,  # anything-llm
    30240,  # bitcoind-knots
    30241,  # bitcoind-knots
    30242,  # bitcoind-knots
    30243,  # linkwarden
    30244,  # wiki-js
    30245,  # wiki-js
    30246,  # element-web
    30247,  # tubearchivist
    30248,  # restic-rest-server
    30249,  # rdt-client
    30250,  # adventurelog
    30251,  # adventurelog
    30252,  # mattermost
    30253,  # mattermost
    30254,  # zoraxy
    30255,  # excalidraw
    30256,  # audiobookshelf
    30257,  # trilium-notes
    30258,  # arcane
    30259,  # opencloud
    30260,  # shelfmark
    30261,  # docspell
    30262,  # openclaw
    30263,  # cleanuparr
    30264,  # retrom
    30265,  # meshcentral
    30266,  # copyparty
    30267,  # nevu
    30268,  # opencloud
    30269,  # nextpvr
    30270,  # channels-dvr
    30271,  # piped
    30272,  # piped
    30273,  # piped
    30274,  # timelinize
    30275,  # coolify
    30276,  # coolify
    30277,  # coolify
    30278,  # music-assistant
    30279,  # music-assistant
    30280,  # radicale
    30281,  # archisteamfarm
    30282,  # yamtrack
    30283,  # dockpeek
    30284,  # librechat
    30285,  # miniflux
    30286,  # localai
    30287,  # gatus
    30288,  # openarchiver
    30289,  # bentopdf
    30290,  # tandoor-recipes
    30291,  # vitransfer
    30292,  # rustfs
    30293,  # rustfs
    30294,  # mkfd
    30295,  # signal-cli-rest-api
    30296,  # seaweedfs
    30297,  # seaweedfs
    30298,  # seaweedfs
    30299,  # seaweedfs
    30300,  # seaweedfs
    30301,  # seaweedfs
    30302,  # seaweedfs
    30303,  # seaweedfs
    30304,  # seaweedfs
    30305,  # lens
    30306,  # lens
    30307,  # media-manager
    30308,  # mydia
    30309,  # mkvtoolnix
    30310,  # tinyauth
    30311,  # memos
    30312,  # papra
    30313,  # bichon
    30314,  # zerobyte
    30315,  # mail-archiver
    30316,  # tracearr
    30317,  # domain-watchdog
    30318,  # qui
    30319,  # concourse
    30320,  # aistor
    30321,  # aistor
    30322,  # n8n
    30323,  # rackula
    30324,  # omnom
    30325,  # lldap
    30326,  # lldap
    30327,  # lldap
    30328,  # dockhand
    30329,  # backrest
    30330,  # mailpit
    30331,  # mailpit
    30332,  # mailpit
    30333,  # beszel-hub
    30334,  # filebrowser-quantum
    30335,  # llmspy
    30336,  # slskd
    30337,  # slskd
    30338,  # zammad
    30339,  # anki-sync-server
    30340,  # stalwart
    30341,  # stalwart
    30342,  # stalwart
    30343,  # stalwart
    30344,  # stalwart
    30345,  # stalwart
    30346,  # stalwart
    30347,  # stalwart
    30348,  # stalwart
    30349,  # stalwart
    30350,  # lubelogger
    30351,  # termix
    30352,  # termix
    30353,  # donetick
    30354,  # omada-controller
    30355,  # versitygw
    30356,  # dispatcharr
    30357,  # seerr
    30358,  # onepassword-connect
    30359,  # onepassword-connect
    30360,  # npmplus
    30361,  # npmplus
    30362,  # npmplus
    30363,  # immich
    30364,  # immich
    30365,  # seaweedfs
    30366,  # seaweedfs
    30367,  # seaweedfs
    30368,  # seaweedfs
    30369,  # seaweedfs
    30370,  # seaweedfs
    30371,  # seaweedfs
    30372,  # seaweedfs
    30373,  # seaweedfs
    30374,  # seaweedfs
    30375,  # aiostreams
    30376,  # domain-locker
    30377,  # open-terminal
    30378,  # bookshelf
    30379,  # boxarr
    30380,  # hyos
    30381,  # hyos
    30382,  # hyos
    30383,  # split-pro
    30384,  # traefik
    30385,  # zabbix
    30386,  # zabbix
    30387,  # fladder
    30388,  # three-proxy
    30389,  # three-proxy
    30390,  # evcc
    30391,  # toparr
    30392,  # pulsarr
    30393,  # reactive-resume
    30394,  # continuwuity
    30395,  # termix
    30396,  # grimmory
    30397,  # stdapi-ai
    30398,  # terraria-tshock
    30399,  # terraria-tshock
    30400,  # openuem
    30401,  # openuem
    30402,  # openuem
    30403,  # openuem
    30404,  # sure
    30405,  # databasus
    30406,  # borgwarehouse
    30407,  # borgwarehouse
    30408,  # immich-kiosk
    30409,  # cloudreve
    30410,  # teslamate
    30411,  # teslamate
    30412,  # blinko
    30413,  # qdrant
    30414,  # qdrant
    30415,  # netbird-server
    30416,  # netbird-server
    30417,  # netbird-server
    30418,  # anki-sync-server
    30419,  # game-vault
    30420,  # game-vault
    30421,  # vane
    30422,  # vllm
    30423,  # meilisearch
    30424,  # gameyfin
    30425,  # immich-frame
    30426,  # glance
    30427,  # clonarr
    30428,  # snapotter
    30429,  # bulwark-webmail
    30430,  # wallabag
    30431,  # audiomuse-ai
    30432,  # hermes-agent
    30433,  # hermes-agent
    30434,  # peertube
    30435,  # peertube
    30436,  # smart-home-dashboard
    30437,  # calibre-web-automated
    30438,  # calagopus
    30439,  # calagopus
    30440,  # hermes-agent
    30441,  # bookorbit
    30442,  # odysseus
    30443,  # palworld
    30444,  # ae-netscope
    30445,  # gptwol
    30446,  # bambuddy
    30447,  # seafile
    30448,  # sparkyfitness
    30449,  # languagetool
    30450,  # openhabittracker
    30451,  # nexus
    30452,  # plainnvr
    30453,  # plainnvr
    30454,  # plainnvr
    30455,  # stlquest
    30456,  # powerbeacon
    30457,  # metatana
    30458,  # poznote
    30459,  # poznote
    30460,  # trawl
    30461,  # eurooffice-document-server
    30462,  # swiparr
    30463,  # ghostfolio
    30464,  # remux
    30465,  # chaptarr
    30466,  # ratelog
    30467,  # arr-dashboard
    30468,  # spotify-to-plex
    30469,  # libredb-studio
    30470,  # yunkan
    30471,  # cinedock
    30472,  # cantinarr
    30473,  # byb-budget
    30474,  # nzbfast
    30475,  # rtsp-stream-hub
    30476,  # keeyo
    30477,  # nexview
    30478,  # travelbuff
    30479,  # tracefinity
    30480,  # switch-game-catalog
    30481,  # arrvantage
    30482,  # dbrepairs
    30483,  # momentbackup-hub
    30484,  # subsimail
    30485,  # fliks
    30486,  # rotki
    30487,  # actuallyfreecd
    30488,  # openfamily
    30489,  # futo-notes
    30490,  # nexmail
    30491,  # vaultbridge
    30492,  # archivebox
    30493,  # nextcloud
    30494,  # autoxpose
    30495,  # nexdeck
    30496,  # nexpulse
    30497,  # nexbeat
    30498,  # keepass-deltasync
    30499,  # hermes-agent
    30500,  # umlautadaptarrex
    30501,  # umlautadaptarrex
    30502,  # umlautadaptarrex
    30503,  # sportarr
    30504,  # freelisten
    30505,  # nexbrand
    30506,  # cloudgate
    30507,  # nexcrate
    30508,  # nextrmnl
    30509,  # photostructure
    30510,  # nexsift
    30511,  # nexsift
    30512,  # nexsift
    30513,  # nexsift
    30514,  # nexsift
    30515,  # airwave
    30516,  # airwave
    30517,  # airwave
    30518,  # nexcanvas
    30519,  # plmail
    30520,  # nexlore
    30521,  # mediathek-stremio
    30522,  # kometa-quickstart
    30523,  # nexdiary
    30524,  # tmodloader
    30525,  # tmodloader
    30880,  # wealthfolio
    31000,  # aistor
    31001,  # aistor
    31003,  # dashy
    31007,  # roundcube
    31008,  # invidious
    31009,  # netbootxyz
    31010,  # netbootxyz
    31011,  # netbootxyz
    31012,  # actual-budget
    31013,  # organizr
    31014,  # dockge
    31015,  # portainer
    31016,  # portainer
    31017,  # portainer
    31027,  # penpot
    31028,  # open-webui
    31050,  # uptime-kuma
    31053,  # filestash
    31054,  # scrutiny
    31055,  # scrutiny
    31061,  # wyze-bridge
    31062,  # wyze-bridge
    31063,  # wyze-bridge
    31064,  # wyze-bridge
    31065,  # wyze-bridge
    31066,  # wyze-bridge
    31067,  # calibre-web
    31089,  # lazylibrarian
    31100,  # steam-headless
    31101,  # lyrion-music-server
    31102,  # lyrion-music-server
    31105,  # invoice-ninja
    31106,  # jelu
    31107,  # tianji
    31116,  # handbrake-web
    32014,  # calibre
    32015,  # calibre
    32016,  # calibre
    32400,  # plex
    32443,  # dropgate-server
    33000,  # hoppscotch
    33100,  # hoppscotch
    33170,  # hoppscotch
    33200,  # hoppscotch
    34197,  # factorio
    35623,  # urbackup
    36052,  # esphome
    37889,  # p2pool
    38211,  # palworld
    38212,  # palworld
)

# Ports added to every standard scan on top of nmap --top-ports: local AI/LLM APIs plus
# web-app dev servers. De-duplicated and sorted. TrueNAS catalog ports are intentionally
# excluded - see TRUENAS_APPS_TCP_PORTS.
STANDARD_EXTRA_TCP_PORTS: tuple[int, ...] = tuple(sorted(set(AI_LLM_TCP_PORTS) | set(WEB_DEV_TCP_PORTS)))

# Telephony signaling ports are never probed: -sV probes into SCCP/SIP/H.323/CTI listeners have
# repeatedly crashed Cisco CUCM and similar call servers. H.323, SCCP, SCCP-TLS, CTI, SIP, SIP-TLS.
NEVER_PROBE_TCP_PORTS: tuple[int, ...] = (1720, 2000, 2443, 2748, 5060, 5061)

# Short list for host-discovery SYN/connect probes (keep discovery cheap): the AI API ports
# plus the handful of dev-server ports that most often identify a live app box.
AI_LLM_DISCOVERY_TCP_PORTS: tuple[int, ...] = (
    1234, 1337, 4891, 9997, 11434,  # AI/LLM APIs
    3000, 5000, 5173, 8000,         # web-app dev servers
)

# Ports that often speak HTTP even when nmap leaves service empty/unknown.
# Again: candidates for web capture only - not product labels.
AI_LLM_WEB_PORTS: frozenset[int] = frozenset(AI_LLM_TCP_PORTS) | frozenset(WEB_DEV_TCP_PORTS)


def merge_port_scope(base: str | None, extra_ports: tuple[int, ...] | list[int]) -> str | None:
    """Append any extra TCP ports not already covered by an nmap services= scope."""
    extras = sorted({int(p) for p in extra_ports if 1 <= int(p) <= 65535})
    if not extras:
        return base
    if not base:
        return PortScope.from_ports(extras)
    scope = PortScope(base)
    missing = [p for p in extras if p not in scope]
    if not missing:
        return base
    return f"{base},{PortScope.from_ports(missing)}"


def mock_standard_scope(base: str = "1-10000") -> str:
    """Mock standard scans cover the usual low ports plus AI/LLM and web-dev candidate ports."""
    return merge_port_scope(base, STANDARD_EXTRA_TCP_PORTS) or base

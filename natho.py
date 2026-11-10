# =========================================================
# NATHO — Plateforme d'apprentissage de l'allemand A1
# Version finale stable : Sidebar + W-Fragen + Audio
# + Apprendre à parler + Essentiels A1 + Mode nuit + Menu mobile
# + NOM/AKK (Nominativ vs Akkusativ) + NEFERTI (bot Sprechen)
# v4.1 : correctifs (sécurité, playlists, progression, Goethe, Neferti, contenu)
# v4.3 : Neferti (recommencer, présentation unique, micro à envoi manuel) + Guide (alphabet, 450 verbes, séparables, Perfekt)
# v4.2 : sécurité renforcée, cours Datif/Génitif, Neferti intelligente (1000+ questions), dialogues uniques
# =========================================================

import os
import sqlite3
import hashlib
import secrets
import json
import random
import re
import stat
import hmac
import time
from html import escape as h
from urllib.parse import urlparse
from collections import deque
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (Flask, request, session, redirect, url_for,
                   g, flash, jsonify,
                   get_flashed_messages, send_file, make_response)

try:
    from gtts import gTTS
    TTS_OK = True
except Exception:
    gTTS = None
    TTS_OK = False

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
DATA_DIR = "/app/data"
DB_PATH = os.path.join(DATA_DIR, "natho.db")

try:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.chmod(DATA_DIR, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
except Exception as e:
    print("Attention dossier data :", e)

def _load_secret():
    """Clé de session STABLE : variable NATHO_SECRET, sinon fichier persistant dans /app/data
    (plus de déconnexion générale à chaque déploiement, identique pour tous les workers)."""
    env = os.environ.get("NATHO_SECRET")
    if env:
        return env
    path = os.path.join(DATA_DIR, ".secret_key")
    for _ in range(5):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                val = fh.read().strip()
            if val:
                return val
        except Exception:
            pass
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            val = secrets.token_hex(32)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(val)
            return val
        except FileExistsError:
            time.sleep(0.2)
        except Exception as e:
            print("Attention clé secrète :", e)
            break
    return secrets.token_hex(32)

APP_SECRET = _load_secret()

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("NATHO_COOKIE_SECURE") or os.environ.get("RAILWAY_ENVIRONMENT")),
    MAX_CONTENT_LENGTH=1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    SESSION_COOKIE_NAME="natho_session",
    JSON_AS_ASCII=False,
)

# ---------------------------------------------------------
# BASE DE DONNÉES
# ---------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA busy_timeout=30000")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# Empreinte (SHA-256) de l'ancien mot de passe admin écrit en dur : sert uniquement à le détecter et à le remplacer.
_COMPROMISED_ADMIN_HASH = "0d78ac587831c938635fccd39ed9ad5f21530703a548079554e2a282908c19ae"

ADMIN_EMAIL = "admin@natho.com"
# Mot de passe admin : JAMAIS en clair dans le code, uniquement son empreinte salée (PBKDF2-SHA256, 600 000 itérations).
# Pour le changer : variable NATHO_ADMIN_PASSWORD (Railway) ou la page « Mon compte ».
_ADMIN_BOOT_HASH = "pbkdf2:sha256:600000$osvkAwWrebuOsaAz$c03ae22c9a1cc2694028997b50286730043e1cbdd8784fac2d64e2172f549516"
_ADMIN_ALT_HASH = "pbkdf2:sha256:600000$8yMoOTeQdHUNZNmo$2558dbbe52afe63c27efadf84d7ccb75f20f7652e2caf45ff8144bc1f769d80d"   # variante tolérée tant que le mot de passe initial n'a pas été changé

def _legacy_hash(pwd: str) -> str:
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()

def hash_pwd(pwd: str) -> str:
    """Hachage salé (PBKDF2-SHA256)."""
    return generate_password_hash(pwd, method="pbkdf2:sha256", salt_length=16)

def _is_legacy_hash(stored: str) -> bool:
    return not (stored or "").startswith(("pbkdf2:", "scrypt:"))

def _admin_alt_ok(row, pwd):
    try:
        return (row["email"] == ADMIN_EMAIL and row["password"] == _ADMIN_BOOT_HASH
                and check_password_hash(_ADMIN_ALT_HASH, pwd))
    except Exception:
        return False

def check_pwd(stored: str, pwd: str) -> bool:
    """Accepte les nouveaux hachages salés ET les anciens SHA-256 (migrés au prochain login réussi)."""
    if not stored:
        return False
    if not _is_legacy_hash(stored):
        try:
            return check_password_hash(stored, pwd)
        except Exception:
            return False
    return hmac.compare_digest(stored, _legacy_hash(pwd))

def init_db():
    try:
        db = sqlite3.connect(DB_PATH, timeout=30)
        try:
            db.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        c = db.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")

        admin_email = ADMIN_EMAIL
        admin_env_pwd = os.environ.get("NATHO_ADMIN_PASSWORD", "")
        c.execute("CREATE TABLE IF NOT EXISTS app_meta (k TEXT PRIMARY KEY, v TEXT)")

        c.execute("SELECT id, password FROM users WHERE email=?", (admin_email,))
        admin_row = c.fetchone()
        boot_done = c.execute("SELECT v FROM app_meta WHERE k='admin_boot_v42'").fetchone() is not None

        if not admin_row:
            first = hash_pwd(admin_env_pwd) if admin_env_pwd else _ADMIN_BOOT_HASH
            c.execute("INSERT INTO users(name,email,password,is_admin) VALUES(?,?,?,1)",
                      ("Admin NATHO", admin_email, first))
            c.execute("INSERT OR REPLACE INTO app_meta(k,v) VALUES('admin_boot_v42','1')")
        else:
            stored = admin_row[1]
            if admin_env_pwd:
                if not check_pwd(stored, admin_env_pwd):
                    c.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(admin_env_pwd), admin_row[0]))
                c.execute("INSERT OR REPLACE INTO app_meta(k,v) VALUES('admin_boot_v42','1')")
            elif not boot_done:
                # première exécution de cette version : on remet le mot de passe admin voulu (une seule fois)
                c.execute("UPDATE users SET password=? WHERE id=?", (_ADMIN_BOOT_HASH, admin_row[0]))
                c.execute("INSERT OR REPLACE INTO app_meta(k,v) VALUES('admin_boot_v42','1')")
            elif stored == _COMPROMISED_ADMIN_HASH:
                new_pwd = secrets.token_urlsafe(12)
                c.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(new_pwd), admin_row[0]))
                print("Ancien mot de passe admin remplacé. Nouveau mot de passe temporaire : %s" % new_pwd, flush=True)
            c.execute("UPDATE users SET is_admin=1 WHERE id=?", (admin_row[0],))

        c.execute("""CREATE TABLE IF NOT EXISTS lessons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            level TEXT DEFAULT 'A1',
            title TEXT NOT NULL,
            french TEXT NOT NULL,
            german TEXT NOT NULL,
            order_index INTEGER DEFAULT 0
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS vocab (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            german TEXT NOT NULL,
            french TEXT NOT NULL
        )""")
        
        c.execute("""CREATE TABLE IF NOT EXISTS dialogues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            lines_json TEXT NOT NULL
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            lesson_id INTEGER NOT NULL,
            listened INTEGER DEFAULT 0,
            completed INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, lesson_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(lesson_id) REFERENCES lessons(id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS goethe_exam (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            result_json TEXT NOT NULL,
            taken_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS speak_phrases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            theme TEXT NOT NULL,
            theme_order INTEGER DEFAULT 0,
            fr TEXT NOT NULL,
            de TEXT NOT NULL,
            UNIQUE(fr, de)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS essentials_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fiche_num INTEGER NOT NULL UNIQUE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            explanation TEXT NOT NULL DEFAULT ''
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS speak_playlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            key TEXT NOT NULL,
            title TEXT NOT NULL,
            items_json TEXT NOT NULL,
            UNIQUE(kind, key)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS nomakk_sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sec_num INTEGER NOT NULL UNIQUE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            explanation TEXT NOT NULL DEFAULT ''
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS nomakk_playlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            items_json TEXT NOT NULL
        )""")

        # === NEFERTI : tables (idempotentes, ne touchent pas l'existant) ===
        c.execute("""CREATE TABLE IF NOT EXISTS neferti_scenarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            step_key TEXT NOT NULL UNIQUE,
            neferti_de TEXT NOT NULL,
            neferti_fr TEXT NOT NULL,
            expected_de TEXT NOT NULL DEFAULT '',
            keywords TEXT NOT NULL DEFAULT '',
            followup_yes TEXT DEFAULT '',
            followup_no TEXT DEFAULT '',
            memory_key TEXT DEFAULT '',
            order_index INTEGER DEFAULT 0
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS neferti_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mem_key TEXT NOT NULL,
            mem_value TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, mem_key),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS neferti_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            fr_text TEXT DEFAULT '',
            de_text TEXT DEFAULT '',
            heard_text TEXT DEFAULT '',
            score INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS neferti_bank (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cat TEXT NOT NULL,
            q_de TEXT UNIQUE NOT NULL,
            q_fr TEXT NOT NULL,
            a_de TEXT NOT NULL,
            a_fr TEXT NOT NULL,
            kw TEXT DEFAULT '',
            lvl INTEGER DEFAULT 1,
            pos INTEGER DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS neferti_asked (
            user_id INTEGER NOT NULL,
            bank_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, bank_id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            k TEXT NOT NULL,
            ts REAL NOT NULL
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_k ON login_attempts(k, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_lessons_cat ON lessons(category)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_vocab_cat ON vocab(category)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_neferti_hist_user ON neferti_history(user_id, id)")

        # === SYNCHRONISATION DU CONTENU (idempotente, à chaque démarrage) ===
        # Ajoute ce qui manque et met à jour les fiches / playlists / scénarios modifiés dans le code.
        seed_lessons(c)
        seed_wfragen(c)
        seed_lessons_extra(c)
        seed_dialogues(c)
        seed_vocab(c)
        seed_vocab_extra(c)
        seed_numbers(c)
        seed_speak_phrases(c)
        seed_essentials_cards(c)
        seed_speak_playlists(c)
        seed_nomakk_sections(c)
        seed_nomakk_playlist(c)
        seed_neferti_scenarios(c)
        seed_neferti_bank(c)

        db.commit()
        db.close()
    except Exception as e:
        print("❌ Erreur d'initialisation :", e)
        import traceback
        traceback.print_exc()

# ---------------------------------------------------------
# CONTENU PÉDAGOGIQUE
# ---------------------------------------------------------
# ---------------------------------------------------------
# SYNCHRONISATION DU CONTENU (idempotente : s'exécute à chaque démarrage et
# n'ajoute que ce qui manque, sans jamais supprimer de leçon ni de progression)
# ---------------------------------------------------------
def _sync_lessons(cursor, data):
    existing = {(r[0], r[1]) for r in cursor.execute("SELECT category, german FROM lessons").fetchall()}
    nxt = cursor.execute("SELECT COALESCE(MAX(order_index), -1) FROM lessons").fetchone()[0] + 1
    for cat, de, fr in data:
        if (cat, de) in existing:
            continue
        cursor.execute(
            "INSERT INTO lessons(category,title,french,german,order_index) VALUES(?,?,?,?,?)",
            (cat, de, fr, de, nxt)
        )
        existing.add((cat, de))
        nxt += 1

def _sync_vocab(cursor, data):
    existing = {(r[0], r[1]) for r in cursor.execute("SELECT category, german FROM vocab").fetchall()}
    for cat, de, fr in data:
        if (cat, de) in existing:
            continue
        cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", (cat, de, fr))
        existing.add((cat, de))

NUMBER_WORDS = [
    ("null", "zéro"), ("eins", "un"), ("zwei", "deux"), ("drei", "trois"), ("vier", "quatre"),
    ("fünf", "cinq"), ("sechs", "six"), ("sieben", "sept"), ("acht", "huit"), ("neun", "neuf"),
    ("zehn", "dix"), ("elf", "onze"), ("zwölf", "douze"), ("dreizehn", "treize"),
    ("vierzehn", "quatorze"), ("fünfzehn", "quinze"), ("sechzehn", "seize"),
    ("siebzehn", "dix-sept"), ("achtzehn", "dix-huit"), ("neunzehn", "dix-neuf"), ("zwanzig", "vingt"),
]


# --- Dialogues (50 × 10 répliques, tous différents) ---
DIALOGUES_DATA = [
    ("Au supermarché", [
        ("A", "Entschuldigung, ich suche Reis. Wo finde ich den?", "Excusez-moi, je cherche du riz. Où puis-je en trouver ?"),
        ("B", "Reis steht in Gang vier, im untersten Regal.", "Le riz est dans l'allée quatre, sur l'étagère du bas."),
        ("A", "Haben Sie auch Mehl? Ich möchte heute Abend einen Kuchen backen.", "Avez-vous aussi de la farine ? Je veux faire un gâteau ce soir."),
        ("B", "Mehl finden Sie in Gang drei, gleich neben dem Zucker.", "La farine se trouve dans l'allée trois, juste à côté du sucre."),
        ("A", "Ist der Zucker im Angebot? Da hängt ein gelbes Schild.", "Le sucre est-il en promotion ? Il y a une étiquette jaune."),
        ("B", "Ja, die Packung kostet nur neunundachtzig Cent, aber nur bis Samstag.", "Oui, le paquet ne coûte que quatre-vingt-neuf centimes, mais seulement jusqu'à samedi."),
        ("A", "Dann nehme ich gleich zwei. Wo sind denn die Eier?", "Alors j'en prends deux tout de suite. Et où sont les œufs ?"),
        ("B", "Im Kühlregal ganz hinten, links neben der Butter.", "Au rayon frais tout au fond, à gauche à côté du beurre."),
        ("A", "Prima, jetzt habe ich alles von meiner Einkaufsliste.", "Super, j'ai maintenant tout ce qui était sur ma liste de courses."),
        ("B", "Dann wünsche ich Ihnen viel Spaß beim Backen!", "Alors je vous souhaite beaucoup de plaisir à faire votre gâteau !"),
    ]),
    ("À la gare", [
        ("A", "Verzeihung, mein Zug nach Köln steht nicht mehr auf der Anzeigetafel.", "Pardon, mon train pour Cologne n'apparaît plus sur le panneau d'affichage."),
        ("B", "Der ist leider ausgefallen. Aber um 16:45 Uhr fährt ein Ersatzzug.", "Il a malheureusement été supprimé. Mais un train de remplacement part à 16h45."),
        ("A", "Von welchem Gleis fährt der Ersatzzug ab?", "De quelle voie part le train de remplacement ?"),
        ("B", "Von Gleis neun. Nehmen Sie den Aufzug dort drüben.", "De la voie neuf. Prenez l'ascenseur là-bas."),
        ("A", "Ich habe eine Reservierung. Gilt sie auch für den Ersatzzug?", "J'ai une réservation. Est-elle aussi valable pour le train de remplacement ?"),
        ("B", "Ja, aber einen festen Sitzplatz bekommen Sie leider nicht.", "Oui, mais vous n'aurez malheureusement pas de place assise attribuée."),
        ("A", "Dann komme ich später an. Verpasse ich meinen Anschluss in Köln?", "Alors j'arriverai plus tard. Vais-je rater ma correspondance à Cologne ?"),
        ("B", "Nein, der Zug nach Bonn wartet fünf Minuten auf Anschlussreisende.", "Non, le train pour Bonn attend cinq minutes les voyageurs en correspondance."),
        ("A", "Dann kaufe ich mir noch schnell eine Zeitung für die Fahrt.", "Alors j'achète vite un journal pour le trajet."),
        ("B", "Beeilen Sie sich, der Ersatzzug steht schon am Bahnsteig!", "Dépêchez-vous, le train de remplacement est déjà à quai !"),
    ]),
    ("Au café", [
        ("A", "Na, was darf es heute sein?", "Alors, qu'est-ce que ce sera aujourd'hui ?"),
        ("B", "Einen Cappuccino mit Hafermilch, bitte. Haben Sie die auch?", "Un cappuccino au lait d'avoine, s'il vous plaît. En avez-vous aussi ?"),
        ("A", "Klar, die haben wir. Trinken Sie hier oder nehmen Sie ihn mit?", "Bien sûr, nous en avons. Vous le buvez ici ou vous l'emportez ?"),
        ("B", "Ich bleibe hier. Ich warte auf eine Freundin.", "Je reste ici. J'attends une amie."),
        ("A", "Dann bringe ich ihn Ihnen an den Tisch. Möchten Sie dazu etwas essen?", "Alors je vous l'apporte à la table. Voulez-vous manger quelque chose avec ?"),
        ("B", "Was ist das für ein Gebäck in der Vitrine?", "Qu'est-ce que c'est que cette pâtisserie dans la vitrine ?"),
        ("A", "Das ist Apfelstrudel, noch warm, mit Vanillesoße.", "C'est du strudel aux pommes, encore chaud, avec de la sauce vanille."),
        ("B", "Oh, lecker! Dann bitte zwei Stück, meine Freundin kommt gleich.", "Oh, délicieux ! Alors deux parts, s'il vous plaît, mon amie arrive bientôt."),
        ("A", "Zwei Strudel und einen Cappuccino. Was trinkt Ihre Freundin?", "Deux strudels et un cappuccino. Que boit votre amie ?"),
        ("B", "Das weiß ich noch nicht. Wenn sie zu spät kommt, esse ich beide Stücke allein!", "Je ne sais pas encore. Si elle arrive trop tard, je mangerai les deux parts tout seul !"),
    ]),
    ("Au restaurant", [
        ("A", "Guten Abend, wir haben einen Tisch auf den Namen Okoye reserviert.", "Bonsoir, nous avons réservé une table au nom d'Okoye."),
        ("B", "Ja, bitte folgen Sie mir. Ihr Tisch steht gleich am Fenster.", "Oui, suivez-moi, s'il vous plaît. Votre table est juste près de la fenêtre."),
        ("A", "Ich bin Vegetarier. Gibt es ein Gericht ohne Fleisch?", "Je suis végétarien. Y a-t-il un plat sans viande ?"),
        ("B", "Die Gemüselasagne ist sehr beliebt, sie enthält kein Fleisch.", "Les lasagnes aux légumes sont très appréciées, elles ne contiennent pas de viande."),
        ("A", "Dann nehme ich die Lasagne, und meine Frau isst das Schnitzel mit Pommes.", "Alors je prends les lasagnes, et ma femme mange l'escalope avec des frites."),
        ("B", "Sehr gern. Was darf ich Ihnen zu trinken bringen?", "Très volontiers. Que puis-je vous apporter à boire ?"),
        ("A", "Ein stilles Wasser und eine Apfelschorle, bitte.", "Une eau plate et un jus de pomme pétillant, s'il vous plaît."),
        ("B", "Ich hoffe, es hat Ihnen geschmeckt. Möchten Sie noch einen Nachtisch?", "J'espère que vous avez bien mangé. Voulez-vous encore un dessert ?"),
        ("A", "Es war ausgezeichnet, aber wir sind satt. Wir möchten bitte zahlen.", "C'était excellent, mais nous n'avons plus faim. Nous voudrions payer, s'il vous plaît."),
        ("B", "Das macht achtundvierzig Euro. Ich wünsche Ihnen noch einen schönen Abend!", "Cela fait quarante-huit euros. Je vous souhaite une très bonne soirée !"),
    ]),
    ("À la boulangerie", [
        ("A", "Guten Morgen, Frau Bauer! Sind die Brezeln schon fertig?", "Bonjour, Madame Bauer ! Les bretzels sont-ils déjà prêts ?"),
        ("B", "Noch nicht, sie kommen erst in fünf Minuten aus dem Ofen.", "Pas encore, ils ne sortent du four que dans cinq minutes."),
        ("A", "Kein Problem, ich warte. Ich möchte übrigens auch eine Torte bestellen.", "Pas de problème, j'attends. Je voudrais d'ailleurs aussi commander un gâteau."),
        ("B", "Gern. Für wann brauchen Sie die Torte?", "Volontiers. Pour quand avez-vous besoin du gâteau ?"),
        ("A", "Für Samstagmittag. Mein Sohn wird sechs Jahre alt.", "Pour samedi midi. Mon fils va avoir six ans."),
        ("B", "Wie schön! Soll ich 'Alles Gute' mit Schokolade darauf schreiben?", "Comme c'est beau ! Dois-je écrire « Alles Gute » dessus avec du chocolat ?"),
        ("A", "Ja, und bitte mit Sahne und Erdbeeren.", "Oui, et avec de la crème et des fraises, s'il vous plaît."),
        ("B", "Gut, ich schreibe es auf: Erdbeertorte für Samstag, zwölf Uhr.", "Bien, je le note : gâteau aux fraises pour samedi, douze heures."),
        ("A", "Meine Frau holt sie am Samstag ab. Ich muss leider arbeiten.", "Ma femme viendra le chercher samedi. Je dois malheureusement travailler."),
        ("B", "Die Torte ist rechtzeitig fertig, das verspreche ich Ihnen. Und da kommen schon Ihre Brezeln!", "Le gâteau sera prêt à temps, je vous le promets. Et voilà déjà vos bretzels !"),
    ]),
    ("Au marché", [
        ("A", "Hi! Sind die Mangos schon reif?", "Salut ! Les mangues sont-elles déjà mûres ?"),
        ("B", "Ja, probieren Sie ein Stück. Die sind süß wie Zucker!", "Oui, goûtez un morceau. Elles sont sucrées comme du sucre !"),
        ("A", "Mmh, wirklich köstlich! Was kostet das Kilo?", "Mmh, vraiment délicieux ! Combien coûte le kilo ?"),
        ("B", "Vier Euro das Kilo, aber heute bekommen Sie drei Kilo für zehn Euro.", "Quatre euros le kilo, mais aujourd'hui vous avez trois kilos pour dix euros."),
        ("A", "Das ist ein guter Preis. Haben Sie auch frischen Ingwer?", "C'est un bon prix. Avez-vous aussi du gingembre frais ?"),
        ("B", "Ja, dort im Korb. Wie viel brauchen Sie?", "Oui, là dans le panier. Combien vous en faut-il ?"),
        ("A", "Nur ein kleines Stück. Heute Abend koche ich Hähnchen mit Ingwer.", "Juste un petit morceau. Ce soir je cuisine du poulet au gingembre."),
        ("B", "Hier, das Stück schenke ich Ihnen. Sie sind heute mein erster Kunde.", "Tenez, je vous offre ce morceau. Vous êtes mon premier client aujourd'hui."),
        ("A", "Das ist aber nett von Ihnen! Dann komme ich nächsten Samstag wieder.", "C'est vraiment gentil de votre part ! Alors je reviendrai samedi prochain."),
        ("B", "Machen Sie das! Dann habe ich frische Papayas für Sie.", "Faites donc ça ! J'aurai alors des papayes fraîches pour vous."),
    ]),
    ("À la pharmacie", [
        ("A", "Ich habe eine Frage: Was hilft gegen Mückenstiche?", "J'ai une question : qu'est-ce qui aide contre les piqûres de moustiques ?"),
        ("B", "Haben Sie viele Stiche? Wo jucken sie am meisten?", "Avez-vous beaucoup de piqûres ? Où est-ce que ça gratte le plus ?"),
        ("A", "An den Armen und an den Beinen. Heute Nacht habe ich kaum geschlafen.", "Aux bras et aux jambes. Cette nuit, j'ai à peine dormi."),
        ("B", "Dann empfehle ich Ihnen diese Salbe. Sie kühlt, und der Juckreiz wird schwächer.", "Alors je vous recommande cette pommade. Elle rafraîchit et les démangeaisons diminuent."),
        ("A", "Muss ich sie auf die ganze Haut auftragen?", "Dois-je l'appliquer sur toute la peau ?"),
        ("B", "Nein, nur auf die Stiche, zweimal am Tag. Und nicht kratzen!", "Non, seulement sur les piqûres, deux fois par jour. Et ne grattez pas !"),
        ("A", "Gibt es auch etwas, das die Mücken fernhält?", "Existe-t-il aussi quelque chose qui éloigne les moustiques ?"),
        ("B", "Ja, dieses Spray. Sprühen Sie es abends auf die Haut.", "Oui, ce spray. Vaporisez-le le soir sur la peau."),
        ("A", "Ich nehme beides. Hat das Spray Nebenwirkungen?", "Je prends les deux. Ce spray a-t-il des effets secondaires ?"),
        ("B", "Keine Sorge. Mit Spray und Salbe schlafen Sie heute Nacht endlich ruhig.", "Pas de souci. Avec le spray et la pommade, vous dormirez enfin tranquillement cette nuit."),
    ]),
    ("Chez le médecin", [
        ("A", "Guten Tag, Herr Weber. Was fehlt Ihnen?", "Bonjour, Monsieur Weber. Qu'est-ce qui ne va pas ?"),
        ("B", "Mein Rücken tut seit Montag sehr weh, Frau Doktor.", "J'ai très mal au dos depuis lundi, docteur."),
        ("A", "Haben Sie etwas Schweres getragen?", "Avez-vous porté quelque chose de lourd ?"),
        ("B", "Ja, ich bin am Wochenende umgezogen und habe viele Kartons getragen.", "Oui, j'ai déménagé ce week-end et j'ai porté beaucoup de cartons."),
        ("A", "Bitte beugen Sie sich nach vorn. Tut das weh?", "Penchez-vous en avant, s'il vous plaît. Est-ce que ça fait mal ?"),
        ("B", "Aua, ja! Genau hier unten links.", "Aïe, oui ! Exactement ici en bas à gauche."),
        ("A", "Es ist nichts gebrochen, aber der Muskel ist verspannt. Ich schreibe Sie eine Woche krank.", "Rien n'est cassé, mais le muscle est contracté. Je vous mets en arrêt maladie pour une semaine."),
        ("B", "Eine Woche? Kann ich nicht trotzdem arbeiten?", "Une semaine ? Ne puis-je pas travailler quand même ?"),
        ("A", "Nein, schonen Sie den Rücken. Danach verschreibe ich Ihnen Krankengymnastik.", "Non, ménagez votre dos. Ensuite je vous prescris de la kinésithérapie."),
        ("B", "Na gut. Dann lasse ich die restlichen Kartons eben noch ein paar Wochen stehen!", "Eh bien, tant pis. Alors je laisse les cartons restants là encore quelques semaines !"),
    ]),
    ("Réserver une chambre d'hôtel", [
        ("A", "Gibt es bei Ihnen über Pfingsten noch ein Familienzimmer?", "Avez-vous encore une chambre familiale pour la Pentecôte ?"),
        ("B", "Moment, ich schaue im Computer nach. Für wie viele Personen?", "Un instant, je regarde sur l'ordinateur. Pour combien de personnes ?"),
        ("A", "Für zwei Erwachsene und ein Kind. Wir bringen auch unseren Hund mit.", "Pour deux adultes et un enfant. Nous amenons aussi notre chien."),
        ("B", "Hunde sind bei uns erlaubt, das kostet zehn Euro extra pro Nacht.", "Les chiens sont acceptés chez nous, cela coûte dix euros de plus par nuit."),
        ("A", "Das ist in Ordnung. Haben Sie auch einen Parkplatz?", "C'est d'accord. Avez-vous aussi un parking ?"),
        ("B", "Ja, hinter dem Haus. Der Parkplatz ist im Preis inbegriffen.", "Oui, derrière la maison. Le parking est compris dans le prix."),
        ("A", "Und was kostet das Familienzimmer insgesamt für drei Nächte?", "Et combien coûte la chambre familiale au total pour trois nuits ?"),
        ("B", "Zweihundertachtzig Euro. Wir brauchen eine Anzahlung von fünfzig Euro.", "Deux cent quatre-vingts euros. Il nous faut un acompte de cinquante euros."),
        ("A", "Kann ich die Reservierung stornieren, wenn jemand von uns krank wird?", "Puis-je annuler la réservation si l'un de nous tombe malade ?"),
        ("B", "Bis zwei Tage vorher ist die Stornierung kostenlos. Wir freuen uns auf Sie und Ihren Hund!", "Jusqu'à deux jours avant, l'annulation est gratuite. Nous nous réjouissons de vous accueillir, vous et votre chien !"),
    ]),
    ("Arrivée à l'hôtel", [
        ("A", "Guten Abend, ich bin Samuel Ndongo. Mein Flug hatte Verspätung. Ist mein Zimmer noch frei?", "Bonsoir, je suis Samuel Ndongo. Mon vol a eu du retard. Ma chambre est-elle encore libre ?"),
        ("B", "Aber natürlich, Herr Ndongo. Sie haben Zimmer 214 im zweiten Stock. Hier ist Ihre Schlüsselkarte.", "Mais bien sûr, Monsieur Ndongo. Vous avez la chambre 214 au deuxième étage. Voici votre carte-clé."),
        ("A", "Wie funktioniert die Karte? Muss ich sie in die Tür stecken?", "Comment fonctionne la carte ? Dois-je l'insérer dans la porte ?"),
        ("B", "Nein, halten Sie sie einfach vor das Schloss, dann leuchtet es grün.", "Non, approchez-la simplement de la serrure, elle s'allume alors en vert."),
        ("A", "Entschuldigung, ich bin's noch einmal. In meinem Zimmer ist es eiskalt.", "Excusez-moi, c'est encore moi. Dans ma chambre il fait un froid glacial."),
        ("B", "Oh, das tut mir leid. Ich gebe Ihnen sofort ein anderes Zimmer.", "Oh, je suis désolé. Je vous donne tout de suite une autre chambre."),
        ("A", "Ist das neue Zimmer ruhig? Ich muss morgen früh fit sein.", "La nouvelle chambre est-elle calme ? Je dois être en forme demain matin."),
        ("B", "Ja, es liegt zum Hof hin, da ist es ganz still. Außerdem bringe ich Ihnen eine zweite Decke.", "Oui, elle donne sur la cour, il y règne un grand calme. De plus, je vous apporte une deuxième couverture."),
        ("A", "Das ist sehr freundlich. Gibt es um diese Uhrzeit noch etwas Warmes zu essen?", "C'est très aimable. Y a-t-il encore quelque chose de chaud à manger à cette heure-ci ?"),
        ("B", "Die Küche ist schon geschlossen, aber ich lasse Ihnen eine Suppe aufs Zimmer bringen. Schlafen Sie gut!", "La cuisine est déjà fermée, mais je vous fais monter une soupe dans la chambre. Dormez bien !"),
    ]),
    ("Départ de l'hôtel", [
        ("A", "Darf ich meinen Koffer noch bis heute Abend hierlassen?", "Puis-je laisser ma valise ici jusqu'à ce soir ?"),
        ("B", "Natürlich, dafür haben wir einen Gepäckraum. Haben Sie schon ausgecheckt?", "Bien sûr, nous avons une consigne pour cela. Avez-vous déjà fait votre check-out ?"),
        ("A", "Ja, die Rechnung ist bezahlt. Aber ich habe mein Ladekabel im Zimmer vergessen!", "Oui, la note est réglée. Mais j'ai oublié mon chargeur dans la chambre !"),
        ("B", "Welche Zimmernummer hatten Sie? Ich rufe das Zimmermädchen an.", "Quel était votre numéro de chambre ? J'appelle la femme de chambre."),
        ("A", "Zimmer 305. Das Kabel steckt neben dem Bett in der Steckdose.", "Chambre 305. Le câble est branché à côté du lit, dans la prise."),
        ("B", "Das Zimmermädchen hat es gefunden. Ich lege es zu Ihrem Gepäck.", "La femme de chambre l'a trouvé. Je le mets avec vos bagages."),
        ("A", "Wunderbar. Mein Zug fährt erst am Abend. Was kann ich hier noch besichtigen?", "Merveilleux. Mon train ne part que ce soir. Que puis-je encore visiter ici ?"),
        ("B", "Gehen Sie zur Burg. Sie liegt nur zehn Minuten entfernt, und der Blick ist toll.", "Allez au château fort. Il n'est qu'à dix minutes d'ici et la vue est superbe."),
        ("A", "Bis wann hat die Burg geöffnet?", "Jusqu'à quand le château est-il ouvert ?"),
        ("B", "Bis siebzehn Uhr. Danach können Sie bei uns noch ein Bier trinken, bevor Ihr Zug fährt.", "Jusqu'à dix-sept heures. Ensuite vous pourrez boire une bière chez nous avant le départ de votre train."),
    ]),
    ("À l'aéroport", [
        ("A", "Haben Sie Flüssigkeiten im Handgepäck? Die müssen in den durchsichtigen Beutel.", "Avez-vous des liquides dans votre bagage à main ? Ils doivent aller dans le sachet transparent."),
        ("B", "Nur eine kleine Flasche Wasser und Zahnpasta.", "Seulement une petite bouteille d'eau et du dentifrice."),
        ("A", "Wasser ist leider nicht erlaubt. Bitte trinken Sie es oder werfen Sie die Flasche weg.", "L'eau n'est malheureusement pas autorisée. Buvez-la ou jetez la bouteille, s'il vous plaît."),
        ("B", "Ach so, das wusste ich nicht. Muss ich auch den Laptop aus der Tasche nehmen?", "Ah bon, je ne le savais pas. Dois-je aussi sortir l'ordinateur portable du sac ?"),
        ("A", "Ja, Laptop und Jacke bitte in die graue Schale. Auch den Gürtel.", "Oui, l'ordinateur et la veste dans le bac gris, s'il vous plaît. Et la ceinture aussi."),
        ("B", "Und die Schuhe? Soll ich sie ausziehen?", "Et les chaussures ? Dois-je les enlever ?"),
        ("A", "Nur wenn der Detektor piept. Gehen Sie jetzt bitte durch den Scanner.", "Seulement si le détecteur sonne. Passez maintenant dans le scanner, s'il vous plaît."),
        ("B", "Er hat gepiept! Was habe ich falsch gemacht?", "Il a sonné ! Qu'ai-je fait de travers ?"),
        ("A", "Haben Sie Münzen in der Hosentasche? Legen Sie sie bitte in die Schale.", "Avez-vous des pièces dans la poche de votre pantalon ? Mettez-les dans le bac, s'il vous plaît."),
        ("B", "Stimmt, zehn Euro in Münzen! Das nächste Mal fliege ich ohne Kleingeld.", "C'est vrai, dix euros en pièces ! La prochaine fois, je voyagerai sans monnaie."),
    ]),
    ("Dans le bus", [
        ("A", "Sagen Sie, fährt die Linie zwölf auch am Sonntag?", "Dites, la ligne douze circule-t-elle aussi le dimanche ?"),
        ("B", "Ja, aber am Wochenende nur alle zwanzig Minuten. Schauen Sie auf den Fahrplan.", "Oui, mais le week-end seulement toutes les vingt minutes. Regardez l'horaire."),
        ("A", "Ich habe nur eine Tageskarte. Gilt sie auch hier im Bus?", "Je n'ai qu'un billet journée. Est-il aussi valable dans ce bus ?"),
        ("B", "Ja, Sie müssen sie nur beim Einsteigen entwerten.", "Oui, il suffit de le valider en montant."),
        ("A", "Wie bitte? Was heißt entwerten?", "Pardon ? Que veut dire « entwerten » ?"),
        ("B", "Sie stecken die Karte in den kleinen Kasten dort. Dann stempelt er das Datum.", "Vous glissez la carte dans la petite boîte là-bas. Elle imprime alors la date."),
        ("A", "Aha, jetzt verstehe ich. Gestern habe ich das vergessen und musste eine Strafe zahlen.", "Ah, maintenant je comprends. Hier je l'ai oublié et j'ai dû payer une amende."),
        ("B", "Autsch! Das waren bestimmt sechzig Euro.", "Aïe ! Ça faisait sûrement soixante euros."),
        ("A", "Ja, genau sechzig Euro! Heute passe ich besser auf.", "Oui, exactement soixante euros ! Aujourd'hui je fais plus attention."),
        ("B", "Dann kann ja nichts mehr schiefgehen. In zehn Minuten sind wir am Ziel.", "Alors plus rien ne peut mal tourner. Dans dix minutes nous serons arrivés."),
    ]),
    ("Dans le métro", [
        ("A", "Mensch, Lena, die U-Bahn ist heute aber voll!", "Mince, Lena, le métro est vraiment plein aujourd'hui !"),
        ("B", "Kein Wunder, im Stadion ist heute ein Konzert. Alle wollen dorthin.", "Pas étonnant, il y a un concert au stade aujourd'hui. Tout le monde veut y aller."),
        ("A", "Müssen wir umsteigen, oder fährt diese Linie direkt?", "Devons-nous changer, ou cette ligne va-t-elle directement ?"),
        ("B", "Wir fahren direkt bis zur Endstation. Danach laufen wir noch zehn Minuten.", "Nous allons directement jusqu'au terminus. Ensuite nous marchons encore dix minutes."),
        ("A", "Hast du die Eintrittskarten im Handy, oder hast du sie ausgedruckt?", "Les billets d'entrée sont-ils dans ton téléphone, ou les as-tu imprimés ?"),
        ("B", "Im Handy. Aber mein Akku ist fast leer!", "Dans mon téléphone. Mais ma batterie est presque vide !"),
        ("A", "Ich habe eine Powerbank im Rucksack. Die kannst du benutzen.", "J'ai une batterie externe dans mon sac à dos. Tu peux l'utiliser."),
        ("B", "Du rettest mich! Hör mal, die Durchsage: Wegen einer Störung hält die Bahn kurz.", "Tu me sauves ! Écoute l'annonce : à cause d'un incident, la rame s'arrête brièvement."),
        ("A", "Hoffentlich dauert das nicht lange. Das Konzert beginnt um acht.", "J'espère que ça ne durera pas longtemps. Le concert commence à huit heures."),
        ("B", "Keine Angst, wir sind früh dran. Nach dem Konzert nehmen wir ein Taxi, versprochen!", "N'aie pas peur, nous sommes en avance. Après le concert nous prendrons un taxi, promis !"),
    ]),
    ("En taxi", [
        ("A", "Servus! Zum Messegelände, bitte, Eingang Nord.", "Salut ! Au parc des expositions, s'il vous plaît, entrée nord."),
        ("B", "Alles klar. Fahren Sie zur Messe? Heute ist dort sicher viel los.", "Entendu. Vous allez au salon ? Il y aura sûrement beaucoup de monde aujourd'hui."),
        ("A", "Ja, ich habe dort um neun Uhr einen Termin. Schaffen wir das?", "Oui, j'ai rendez-vous là-bas à neuf heures. Y arriverons-nous ?"),
        ("B", "Normalerweise ja, aber auf der Hauptstraße ist eine Baustelle. Ich nehme einen Umweg.", "Normalement oui, mais il y a un chantier sur la rue principale. Je prends un détour."),
        ("A", "Wird der Umweg viel teurer?", "Le détour sera-t-il beaucoup plus cher ?"),
        ("B", "Nein, der Taxameter läuft nach Zeit und Strecke. Es kostet vielleicht zwei Euro mehr.", "Non, le taximètre compte selon le temps et la distance. Cela coûtera peut-être deux euros de plus."),
        ("A", "Das ist in Ordnung. Wie viele Minuten sind es noch?", "C'est d'accord. Combien de minutes reste-t-il ?"),
        ("B", "Ungefähr zwölf. Sehen Sie, jetzt ist die Straße wieder frei.", "Environ douze. Voyez, la route est de nouveau dégagée."),
        ("A", "Prima, dann bin ich sogar zu früh. Kann ich eine Quittung bekommen? Mein Chef bezahlt die Fahrt.", "Super, alors je serai même en avance. Puis-je avoir un reçu ? Mon patron paie la course."),
        ("B", "Natürlich, hier ist sie. Und viel Erfolg auf der Messe, verkaufen Sie viel!", "Bien sûr, la voici. Et bon succès au salon, vendez beaucoup !"),
    ]),
    ("Demander son chemin", [
        ("A", "Entschuldigen Sie, ich habe mich verlaufen. Kennen Sie das Stadtmuseum?", "Excusez-moi, je me suis perdu. Connaissez-vous le musée municipal ?"),
        ("B", "Aber ja! Sie sind schon ganz nah. Gehen Sie bis zur Ampel.", "Mais oui ! Vous en êtes tout près. Allez jusqu'au feu."),
        ("A", "Bis zur Ampel dort vorn? Und dann links oder rechts?", "Jusqu'au feu là-devant ? Et ensuite à gauche ou à droite ?"),
        ("B", "Dort biegen Sie links ab und gehen über die Brücke.", "Là vous tournez à gauche et traversez le pont."),
        ("A", "Über die Brücke ... Und danach?", "Sur le pont... Et après ?"),
        ("B", "Danach sehen Sie links einen großen Platz mit einem Brunnen.", "Ensuite vous voyez à gauche une grande place avec une fontaine."),
        ("A", "Ist das Museum direkt am Platz?", "Le musée est-il directement sur la place ?"),
        ("B", "Ja, es liegt dem Brunnen gegenüber. Das Gebäude ist grau und hat rote Fenster.", "Oui, il se trouve en face de la fontaine. Le bâtiment est gris et a des fenêtres rouges."),
        ("A", "Super, das finde ich! Wie weit ist es ungefähr?", "Super, je le trouverai ! À quelle distance est-ce environ ?"),
        ("B", "Nur etwa zehn Minuten. Sie können es wirklich nicht verfehlen.", "Seulement dix minutes environ. Vous ne pouvez vraiment pas le rater."),
    ]),
    ("Se présenter", [
        ("A", "Hi, ich bin Fatou. Ist hier noch ein Platz frei?", "Salut, je suis Fatou. Y a-t-il encore une place libre ici ?"),
        ("B", "Klar, setz dich! Ich bin Paul. Bist du zum ersten Mal beim Sprachcafé?", "Bien sûr, assieds-toi ! Je suis Paul. Est-ce ta première fois au café des langues ?"),
        ("A", "Ja, zum ersten Mal. Ich komme aus Yaoundé und lerne seit drei Monaten Deutsch.", "Oui, la première fois. Je viens de Yaoundé et j'apprends l'allemand depuis trois mois."),
        ("B", "Dein Deutsch ist schon sehr gut! Ich lerne Französisch, deshalb können wir beide üben.", "Ton allemand est déjà très bon ! J'apprends le français, donc nous pouvons tous les deux nous entraîner."),
        ("A", "Super, dann üben wir zusammen! Was machst du in deiner Freizeit, Paul?", "Super, alors nous nous entraînons ensemble ! Que fais-tu pendant ton temps libre, Paul ?"),
        ("B", "Ich spiele Gitarre und fahre gern Rad. Und du?", "Je joue de la guitare et j'aime faire du vélo. Et toi ?"),
        ("A", "Ich tanze gern und koche. Mein Lieblingsessen ist Ndolé.", "J'aime danser et cuisiner. Mon plat préféré est le ndolé."),
        ("B", "Ndolé? Das kenne ich nicht. Was ist das?", "Du ndolé ? Je ne connais pas. Qu'est-ce que c'est ?"),
        ("A", "Ein Gericht mit Bitterblättern, Erdnüssen und Fisch. Sehr lecker!", "Un plat avec des feuilles amères, des arachides et du poisson. Très bon !"),
        ("B", "Das klingt toll! Hast du Lust, es mir nach dem Kurs einmal zu kochen?", "Ça a l'air génial ! As-tu envie de me le cuisiner un jour après le cours ?"),
    ]),
    ("Rencontrer un voisin", [
        ("A", "Ach, Sie sind der neue Nachbar von nebenan! Ich bin Frau Hoffmann.", "Ah, vous êtes le nouveau voisin d'à côté ! Je suis Madame Hoffmann."),
        ("B", "Freut mich, Frau Hoffmann. Ich heiße Ibrahim und bin gestern eingezogen.", "Enchanté, Madame Hoffmann. Je m'appelle Ibrahim et j'ai emménagé hier."),
        ("A", "Dann erkläre ich Ihnen kurz die Hausordnung. Der Müll wird bei uns getrennt.", "Alors je vous explique brièvement le règlement de l'immeuble. Chez nous, les déchets sont triés."),
        ("B", "Getrennt? Wie funktioniert das genau?", "Triés ? Comment ça marche exactement ?"),
        ("A", "Papier in die blaue Tonne, Plastik in die gelbe und Essensreste in die braune.", "Le papier dans la poubelle bleue, le plastique dans la jaune et les restes de nourriture dans la marron."),
        ("B", "Und wo stehen die Mülltonnen?", "Et où se trouvent les poubelles ?"),
        ("A", "Im Hof, hinter dem Haus. Die Waschküche ist im Keller, den Schlüssel bekommen Sie vom Hausmeister.", "Dans la cour, derrière l'immeuble. La buanderie est à la cave, vous obtenez la clé auprès du concierge."),
        ("B", "Gibt es Ruhezeiten? Ich möchte Sie nicht stören.", "Y a-t-il des heures de silence ? Je ne veux pas vous déranger."),
        ("A", "Ja, mittags von zwölf bis drei und abends nach zehn Uhr soll es leise sein.", "Oui, à midi de douze à trois heures et le soir après dix heures, il faut être silencieux."),
        ("B", "Verstanden, ich merke es mir. Nächste Woche lade ich Sie zur Einweihung auf ein Stück Kuchen ein.", "Compris, je m'en souviendrai. La semaine prochaine je vous invite à pendre la crémaillère autour d'une part de gâteau."),
    ]),
    ("Au téléphone : un rendez-vous", [
        ("A", "Zahnarztpraxis Dr. Braun, mein Name ist Keller. Wie kann ich helfen?", "Cabinet dentaire du docteur Braun, je m'appelle Keller. Comment puis-je vous aider ?"),
        ("B", "Guten Tag, ich möchte einen Termin zur Kontrolle ausmachen.", "Bonjour, je voudrais prendre rendez-vous pour un contrôle."),
        ("A", "Waren Sie schon einmal bei uns?", "Êtes-vous déjà venu chez nous ?"),
        ("B", "Nein, ich bin neu hier und habe seit einer Woche Zahnschmerzen.", "Non, je suis nouveau ici et j'ai mal aux dents depuis une semaine."),
        ("A", "Dann kommen Sie am besten morgen. Um 8:15 Uhr oder um 14 Uhr?", "Alors venez de préférence demain. À 8h15 ou à 14 heures ?"),
        ("B", "Um 14 Uhr passt besser. Morgens muss ich arbeiten.", "14 heures me convient mieux. Le matin je dois travailler."),
        ("A", "Gut. Wie ist Ihr Nachname? Bitte buchstabieren Sie ihn.", "Bien. Quel est votre nom de famille ? Épelez-le, s'il vous plaît."),
        ("B", "Ndiaye: N wie Nordpol, D wie Dora, I wie Ida, A wie Anton, Y wie Ypsilon, E wie Emil.", "Ndiaye : N comme Nordpol, D comme Dora, I comme Ida, A comme Anton, Y comme Ypsilon, E comme Emil (alphabet d'épellation allemand)."),
        ("A", "Bringen Sie bitte Ihre Krankenkassenkarte mit, und kommen Sie zehn Minuten früher.", "Apportez votre carte d'assurance maladie, s'il vous plaît, et venez dix minutes plus tôt."),
        ("B", "Mache ich. Hoffentlich muss der Zahn nicht raus!", "Je le ferai. J'espère qu'il ne faudra pas arracher la dent !"),
    ]),
    ("Au téléphone : en retard", [
        ("A", "Schmidt, guten Morgen.", "Schmidt, bonjour."),
        ("B", "Hier ist Amadou, Frau Schmidt. Mein Zug hat Verspätung, ich komme später.", "C'est Amadou, Madame Schmidt. Mon train a du retard, j'arriverai plus tard."),
        ("A", "Wie viel später denn? Um neun Uhr haben wir den Kundentermin.", "Combien de retard exactement ? À neuf heures nous avons le rendez-vous avec le client."),
        ("B", "Wahrscheinlich eine Dreiviertelstunde. Wir stehen schon seit zwanzig Minuten auf freier Strecke.", "Probablement trois quarts d'heure. Nous sommes arrêtés en pleine voie depuis vingt minutes."),
        ("A", "Hm, das ist schwierig. Haben Sie die Unterlagen für den Kunden dabei?", "Hm, c'est compliqué. Avez-vous les documents pour le client avec vous ?"),
        ("B", "Ja, sie sind in meinem Rucksack. Ich kann sie aber auch per E-Mail schicken.", "Oui, ils sont dans mon sac à dos. Mais je peux aussi les envoyer par e-mail."),
        ("A", "Schicken Sie sie mir bitte sofort. Dann übernehme ich die Präsentation.", "Envoyez-les-moi tout de suite, s'il vous plaît. Alors je me charge de la présentation."),
        ("B", "Mach ich sofort. In zwei Minuten haben Sie die Datei im Postfach.", "Je le fais tout de suite. Dans deux minutes vous aurez le fichier dans votre boîte mail."),
        ("A", "Gut. Und fahren Sie in Zukunft bitte einen Zug früher.", "Bien. Et à l'avenir prenez un train plus tôt, s'il vous plaît."),
        ("B", "Das verspreche ich Ihnen. Beim nächsten Mal bin ich eine Stunde früher da!", "Je vous le promets. La prochaine fois je serai là une heure plus tôt !"),
    ]),
    ("À la banque", [
        ("A", "Wie kann ich Geld an meine Mutter nach Kamerun überweisen?", "Comment puis-je envoyer de l'argent à ma mère au Cameroun ?"),
        ("B", "Das geht per Auslandsüberweisung. Haben Sie die Kontodaten Ihrer Mutter?", "Cela se fait par virement international. Avez-vous les coordonnées bancaires de votre mère ?"),
        ("A", "Ich habe nur den Namen und die Kontonummer, aber keine IBAN.", "J'ai seulement le nom et le numéro de compte, mais pas d'IBAN."),
        ("B", "Ohne IBAN und BIC geht es leider nicht. Können Sie Ihre Mutter kurz anrufen?", "Sans IBAN et BIC, ce n'est malheureusement pas possible. Pouvez-vous appeler brièvement votre mère ?"),
        ("A", "Moment ... Sie schickt mir die Nummern per Nachricht. Hier sind sie.", "Un instant... Elle m'envoie les numéros par message. Les voici."),
        ("B", "Sehr gut. Wie viel möchten Sie überweisen?", "Très bien. Combien voulez-vous virer ?"),
        ("A", "Zweihundert Euro. Was kostet das an Gebühren?", "Deux cents euros. Combien cela coûte-t-il en frais ?"),
        ("B", "Die Gebühr beträgt fünfzehn Euro. Den Wechselkurs sehen Sie auf diesem Zettel.", "Les frais s'élèvent à quinze euros. Vous voyez le taux de change sur ce papier."),
        ("A", "Wann kommt das Geld in Kamerun an?", "Quand l'argent arrive-t-il au Cameroun ?"),
        ("B", "In der Regel nach zwei bis drei Werktagen, also spätestens am Donnerstag.", "En règle générale après deux à trois jours ouvrables, donc au plus tard jeudi."),
    ]),
    ("À la poste", [
        ("A", "Eine Bewerbung per Einschreiben, bitte. Wie funktioniert das?", "Une candidature en recommandé, s'il vous plaît. Comment ça marche ?"),
        ("B", "Dann brauche ich den Brief. Ist er schon in einem Umschlag?", "Alors il me faut la lettre. Est-elle déjà dans une enveloppe ?"),
        ("A", "Ja, hier. Wie muss ich die Adresse schreiben?", "Oui, voici. Comment dois-je écrire l'adresse ?"),
        ("B", "Links oben steht der Absender, rechts unten der Empfänger mit der Postleitzahl.", "En haut à gauche, l'expéditeur, en bas à droite, le destinataire avec le code postal."),
        ("A", "Die Firma sitzt in Leipzig. Die Postleitzahl ist null-vier-eins-null-neun.", "L'entreprise est à Leipzig. Le code postal est zéro-quatre-un-zéro-neuf."),
        ("B", "Gut. Möchten Sie einen Rückschein? Dann bekommen Sie eine Bestätigung, dass der Brief angekommen ist.", "Bien. Voulez-vous un accusé de réception ? Vous aurez ainsi la confirmation que la lettre est arrivée."),
        ("A", "Ja, bitte. Was kostet das alles zusammen?", "Oui, s'il vous plaît. Combien cela coûte-t-il en tout ?"),
        ("B", "Das Einschreiben kostet vier Euro, der Rückschein noch einmal einen Euro fünfzig extra.", "Le recommandé coûte quatre euros, l'accusé de réception un euro cinquante de plus."),
        ("A", "Bis wann ist der Brief in Leipzig? Die Frist endet am Freitag.", "Quand la lettre sera-t-elle à Leipzig ? Le délai se termine vendredi."),
        ("B", "Morgen oder übermorgen. Dann drücke ich Ihnen die Daumen für die Stelle!", "Demain ou après-demain. Alors je croise les doigts pour vous pour ce poste !"),
    ]),
    ("Au magasin de vêtements", [
        ("A", "Schauen Sie, diesen Pullover habe ich gestern gekauft, aber er ist zu eng.", "Regardez, j'ai acheté ce pull hier, mais il est trop serré."),
        ("B", "Haben Sie den Kassenzettel noch? Dann können Sie ihn umtauschen.", "Avez-vous encore le ticket de caisse ? Alors vous pouvez l'échanger."),
        ("A", "Ja, hier ist er. Gibt es den Pullover auch eine Größe größer?", "Oui, le voici. Y a-t-il ce pull aussi en une taille au-dessus ?"),
        ("B", "Ich sehe nach. In Grau haben wir Größe L, in Blau leider nicht mehr.", "Je regarde. En gris nous avons la taille L, en bleu malheureusement plus."),
        ("A", "Grau ist mir zu langweilig. Haben Sie ihn vielleicht in Grün?", "Le gris est trop ennuyeux pour moi. L'avez-vous peut-être en vert ?"),
        ("B", "Grün haben wir nur noch in M. Möchten Sie lieber einen Gutschein?", "Le vert, nous ne l'avons plus qu'en M. Préférez-vous un bon d'achat ?"),
        ("A", "Wofür gilt der Gutschein?", "Pour quoi ce bon est-il valable ?"),
        ("B", "Sie können ihn ein Jahr lang im ganzen Geschäft benutzen, auch für Hosen oder Schuhe.", "Vous pouvez l'utiliser pendant un an dans tout le magasin, aussi pour des pantalons ou des chaussures."),
        ("A", "Dann nehme ich den Gutschein. Die Schuhe dort sind sowieso viel schöner als der Pullover.", "Alors je prends le bon. Ces chaussures là-bas sont de toute façon bien plus belles que le pull."),
        ("B", "Probieren Sie die Schuhe aber diesmal vor dem Kauf an!", "Mais essayez les chaussures avant de les acheter, cette fois !"),
    ]),
    ("Au magasin de téléphones", [
        ("A", "Hallo, ich brauche eine deutsche SIM-Karte. Welche Tarife haben Sie?", "Bonjour, il me faut une carte SIM allemande. Quels forfaits avez-vous ?"),
        ("B", "Möchten Sie einen Vertrag oder eine Prepaid-Karte?", "Voulez-vous un contrat ou une carte prépayée ?"),
        ("A", "Ich bleibe nur sechs Monate hier. Was ist besser?", "Je ne reste ici que six mois. Qu'est-ce qui est mieux ?"),
        ("B", "Dann empfehle ich Prepaid. Da gibt es keinen Vertrag, und Sie können jederzeit wechseln.", "Alors je recommande la prépayée. Il n'y a pas de contrat et vous pouvez changer à tout moment."),
        ("A", "Wie viel Datenvolumen bekomme ich?", "Combien de données mobiles ai-je ?"),
        ("B", "Zehn Gigabyte für fünfzehn Euro im Monat. Telefonieren in Deutschland ist inklusive.", "Dix gigaoctets pour quinze euros par mois. Les appels en Allemagne sont inclus."),
        ("A", "Ich telefoniere viel mit meiner Familie in Kamerun. Geht das auch?", "J'appelle beaucoup ma famille au Cameroun. Est-ce possible aussi ?"),
        ("B", "Das kostet extra. Aber mit WhatsApp telefonieren Sie über das Datenvolumen.", "Cela coûte en plus. Mais avec WhatsApp vous appelez avec vos données mobiles."),
        ("A", "Ach so, das ist praktisch. Wie lade ich das Guthaben auf?", "Ah bon, c'est pratique. Comment recharger mon crédit ?"),
        ("B", "Ganz einfach: im Supermarkt an der Kasse oder per App. Dann kann Ihre Familie Sie bald anrufen.", "Très simple : au supermarché à la caisse ou par appli. Alors votre famille pourra bientôt vous appeler."),
    ]),
    ("À la bibliothèque", [
        ("A", "Leider sind meine Bücher seit einer Woche überfällig. Was muss ich jetzt tun?", "Malheureusement mes livres sont en retard depuis une semaine. Que dois-je faire maintenant ?"),
        ("B", "Das ist nicht schlimm. Die Mahngebühr beträgt zehn Cent pro Tag und Buch.", "Ce n'est pas grave. La pénalité de retard est de dix centimes par jour et par livre."),
        ("A", "Ich habe drei Bücher. Wie viel muss ich bezahlen?", "J'ai trois livres. Combien dois-je payer ?"),
        ("B", "Drei Bücher, sieben Tage: Das macht zwei Euro zehn.", "Trois livres, sept jours : cela fait deux euros dix."),
        ("A", "Hier, bitte. Kann ich ein Buch noch einmal verlängern? Ich bin nicht fertig.", "Tenez. Puis-je encore renouveler un livre ? Je n'ai pas fini."),
        ("B", "Ja, einmal. Das geht auch online mit Ihrer Kundennummer.", "Oui, une fois. Cela se fait aussi en ligne avec votre numéro de client."),
        ("A", "Gut. Und gibt es hier einen ruhigen Platz zum Lernen?", "Bien. Et y a-t-il ici un endroit calme pour étudier ?"),
        ("B", "Im Lesesaal im ersten Stock. Dort darf man nicht telefonieren und nicht essen.", "Dans la salle de lecture au premier étage. On n'y a le droit ni de téléphoner ni de manger."),
        ("A", "Ich muss auch ein paar Seiten kopieren. Gibt es einen Kopierer?", "Je dois aussi photocopier quelques pages. Y a-t-il une photocopieuse ?"),
        ("B", "Ja, neben dem Eingang. Aber bitte bringen Sie die Bücher nächstes Mal pünktlich zurück!", "Oui, à côté de l'entrée. Mais rapportez les livres à temps la prochaine fois, s'il vous plaît !"),
    ]),
    ("Au cours d'allemand", [
        ("A", "Moin! Hast du die Hausaufgabe schon gemacht?", "Salut ! As-tu déjà fait les devoirs ?"),
        ("B", "Nein, die Artikel machen mich verrückt. Warum heißt es der Tisch, aber die Lampe?", "Non, les articles me rendent fou. Pourquoi dit-on « der Tisch » mais « die Lampe » ?"),
        ("A", "Dafür gibt es keine feste Regel. Du musst jedes Wort mit dem Artikel lernen.", "Il n'y a pas de règle fixe pour ça. Il faut apprendre chaque mot avec son article."),
        ("B", "Das ist so anstrengend! Wie lernst du die Wörter?", "C'est tellement fatigant ! Comment apprends-tu les mots ?"),
        ("A", "Ich klebe kleine Zettel an alle Dinge in meiner Wohnung.", "Je colle de petits papiers sur toutes les choses de mon appartement."),
        ("B", "Die Idee ist gut! Dann sehe ich die Artikel jeden Tag.", "Bonne idée ! Alors je vois les articles tous les jours."),
        ("A", "Genau. Und vor der Prüfung nächste Woche fragen wir uns gegenseitig ab.", "Exactement. Et avant l'examen de la semaine prochaine, nous nous interrogeons mutuellement."),
        ("B", "Ich habe Angst vor dem mündlichen Teil.", "J'ai peur de l'épreuve orale."),
        ("A", "Du sprichst doch schon gut! Du musst nur keine Angst vor Fehlern haben.", "Mais tu parles déjà bien ! Il ne faut juste pas avoir peur des erreurs."),
        ("B", "Dann lernen wir ab heute jeden Abend zusammen. Einverstanden?", "Alors nous apprenons ensemble tous les soirs à partir d'aujourd'hui. D'accord ?"),
    ]),
    ("À l'université", [
        ("A", "Hast du kurz Zeit? Ich verstehe meinen Stundenplan nicht.", "As-tu un instant ? Je ne comprends pas mon emploi du temps."),
        ("B", "Klar. Zeig mal. Hier steht die Vorlesung, das ist der große Hörsaal.", "Bien sûr. Montre. Ici c'est le cours magistral, dans le grand amphithéâtre."),
        ("A", "Und was ist ein Seminar? Ist das etwas anderes?", "Et qu'est-ce qu'un séminaire ? Est-ce différent ?"),
        ("B", "Ja, im Seminar sind wir weniger Leute, und wir diskutieren. Du musst dort ein Referat halten.", "Oui, au séminaire nous sommes moins nombreux et nous discutons. Tu dois y faire un exposé."),
        ("A", "Ein Referat? Ich muss vor allen sprechen? Das ist schwierig für mich!", "Un exposé ? Je dois parler devant tout le monde ? C'est difficile pour moi !"),
        ("B", "Keine Sorge, das macht jeder einmal im Semester. Mit Notizen geht es gut.", "Pas de souci, tout le monde le fait une fois par semestre. Avec des notes, ça se passe bien."),
        ("A", "Wo bekomme ich meinen Studentenausweis?", "Où puis-je obtenir ma carte d'étudiant ?"),
        ("B", "Im Sekretariat, Zimmer 12. Mit dem Ausweis isst du auch billiger in der Mensa.", "Au secrétariat, salle 12. Avec la carte, tu manges aussi moins cher au restaurant universitaire."),
        ("A", "Sehr gut! Gibt es dort auch vegetarisches Essen?", "Très bien ! Y a-t-il aussi des repas végétariens là-bas ?"),
        ("B", "Klar! Treffen wir uns um halb eins vor der Mensa? Dann zeige ich es dir.", "Bien sûr ! On se retrouve à midi et demi devant le restaurant universitaire ? Je te le montrerai."),
    ]),
    ("Un entretien d'embauche", [
        ("A", "Guten Tag, Herr Okafor. Schön, dass Sie gekommen sind. Bitte setzen Sie sich.", "Bonjour, Monsieur Okafor. Je suis contente que vous soyez venu. Asseyez-vous, je vous prie."),
        ("B", "Guten Tag, Frau Lange. Ich freue mich über die Einladung.", "Bonjour, Madame Lange. Je suis heureux de cette invitation."),
        ("A", "Wo haben Sie bisher gearbeitet?", "Où avez-vous travaillé jusqu'à présent ?"),
        ("B", "Ich habe drei Jahre in einem Hotel in Douala gearbeitet, an der Rezeption.", "J'ai travaillé trois ans dans un hôtel à Douala, à la réception."),
        ("A", "Was waren dort Ihre Aufgaben?", "Quelles étaient vos tâches là-bas ?"),
        ("B", "Ich habe Gäste begrüßt, Zimmer gebucht und Beschwerden bearbeitet.", "J'ai accueilli les clients, réservé des chambres et traité les réclamations."),
        ("A", "Warum möchten Sie jetzt bei uns arbeiten?", "Pourquoi voulez-vous maintenant travailler chez nous ?"),
        ("B", "Weil ich in Deutschland neue Erfahrungen sammeln und mein Deutsch verbessern möchte.", "Parce que je veux acquérir de nouvelles expériences en Allemagne et améliorer mon allemand."),
        ("A", "Die Probezeit dauert sechs Monate, und das Gehalt liegt bei zweitausend Euro brutto.", "La période d'essai dure six mois et le salaire est de deux mille euros brut."),
        ("B", "Das klingt gut. Ich warte gespannt auf Ihren Anruf.", "Cela me convient. J'attends votre appel avec impatience."),
    ]),
    ("Au bureau", [
        ("A", "Willkommen im Team, Herr Diallo! Das hier ist Ihr Schreibtisch.", "Bienvenue dans l'équipe, Monsieur Diallo ! Voici votre bureau."),
        ("B", "Vielen Dank, Frau Klein. Der Platz am Fenster gefällt mir sehr.", "Merci beaucoup, Madame Klein. La place près de la fenêtre me plaît beaucoup."),
        ("A", "Hier ist Ihre Zugangskarte. Damit öffnen Sie die Haustür und das Büro.", "Voici votre badge d'accès. Avec lui vous ouvrez la porte d'entrée et le bureau."),
        ("B", "Und wie bekomme ich meinen Computer-Zugang?", "Et comment obtiens-je mon accès à l'ordinateur ?"),
        ("A", "Die IT schickt Ihnen heute die Daten per E-Mail. Übrigens: Hier duzen wir uns alle.", "Le service informatique vous envoie vos identifiants par e-mail aujourd'hui. D'ailleurs, ici nous nous tutoyons tous."),
        ("B", "Gern. Dann bin ich Moussa. Wann ist die Mittagspause?", "Volontiers. Alors je suis Moussa. Quand est la pause de midi ?"),
        ("A", "Von zwölf bis eins. Ich bin Sabine. Wir essen meistens in der Kantine.", "De midi à une heure. Je suis Sabine. Nous mangeons le plus souvent à la cantine."),
        ("B", "Gibt es dort auch Essen ohne Schweinefleisch? Ich esse kein Schweinefleisch.", "Y a-t-il aussi des repas sans porc là-bas ? Je ne mange pas de porc."),
        ("A", "Ja, jeden Tag gibt es ein Gericht ohne Schwein und ein vegetarisches.", "Oui, chaque jour il y a un plat sans porc et un végétarien."),
        ("B", "Das ist super. Dann komme ich heute gern mit euch in die Kantine.", "C'est super. Alors je viens volontiers avec vous à la cantine aujourd'hui."),
    ]),
    ("Visiter un appartement", [
        ("A", "Darf ich beim Rundgang Fotos machen? Ich möchte sie meiner Frau schicken.", "Puis-je prendre des photos pendant la visite ? Je voudrais les envoyer à ma femme."),
        ("B", "Aber sicher. Das hier ist die Einbauküche. Herd und Kühlschrank sind im Preis dabei.", "Bien sûr. Voici la cuisine équipée. La cuisinière et le réfrigérateur sont compris dans le prix."),
        ("A", "Das ist praktisch. Wie wird die Wohnung geheizt?", "C'est pratique. Comment l'appartement est-il chauffé ?"),
        ("B", "Mit einer Zentralheizung. Das Warmwasser ist inklusive.", "Avec un chauffage central. L'eau chaude est incluse."),
        ("A", "Dürfen wir ein Haustier haben? Wir haben eine kleine Katze.", "Avons-nous le droit d'avoir un animal ? Nous avons une petite chatte."),
        ("B", "Katzen sind kein Problem.", "Les chats ne posent pas de problème."),
        ("A", "Gibt es einen Kellerraum und einen Platz für unsere Fahrräder?", "Y a-t-il une cave et un endroit pour nos vélos ?"),
        ("B", "Ja, jede Wohnung hat einen Kellerraum, und die Fahrräder stehen im Hof unter dem Dach.", "Oui, chaque logement a une cave, et les vélos sont rangés dans la cour sous un auvent."),
        ("A", "Wie hoch ist die Kaution?", "À combien s'élève la caution ?"),
        ("B", "Drei Monatsmieten, also eintausendachthundert Euro. Soll ich Ihnen den Mietvertrag per E-Mail schicken?", "Trois mois de loyer, soit mille huit cents euros. Dois-je vous envoyer le contrat de location par e-mail ?"),
    ]),
    ("Une fête", [
        ("A", "Schön dich zu sehen! Komm rein, die Party hat schon angefangen.", "Content de te voir ! Entre, la fête a déjà commencé."),
        ("B", "Entschuldige die Verspätung. Ich habe einen Kuchen mitgebracht.", "Excuse mon retard. J'ai apporté un gâteau."),
        ("A", "Oh, super! Stell ihn auf den Tisch in der Küche. Möchtest du was zu trinken?", "Oh, super ! Pose-le sur la table de la cuisine. Veux-tu boire quelque chose ?"),
        ("B", "Hast du Limonade? Ich muss später noch fahren.", "As-tu de la limonade ? Je dois encore conduire plus tard."),
        ("A", "Klar, im Kühlschrank. Und nimm dir ruhig Chips, die sind ganz frisch.", "Bien sûr, au frigo. Et sers-toi des chips, ils sont tout frais."),
        ("B", "Wer sind die vielen Leute? Ich kenne fast niemanden.", "Qui sont tous ces gens ? Je ne connais presque personne."),
        ("A", "Das sind meine Kollegen und ein paar Nachbarn. Ich stelle dich gleich vor.", "Ce sont mes collègues et quelques voisins. Je te présente tout de suite."),
        ("B", "Die Musik ist ziemlich laut. Beschweren sich die Nachbarn nicht?", "La musique est assez forte. Les voisins ne se plaignent-ils pas ?"),
        ("A", "Nein, sie sind ja selbst da! Hör mal, jetzt läuft dein Lieblingslied.", "Non, ils sont là eux-mêmes ! Écoute, voilà ta chanson préférée."),
        ("B", "Dann trinken wir auf die Nachbarn: Prost! Und jetzt tanzen wir!", "Alors buvons aux voisins : santé ! Et maintenant, dansons !"),
    ]),
    ("Un anniversaire", [
        ("A", "Psst! Nächsten Freitag hat Lena Geburtstag. Wir machen eine Überraschung.", "Chut ! Vendredi prochain, c'est l'anniversaire de Lena. Nous préparons une surprise."),
        ("B", "Gute Idee! Wo werden wir feiern?", "Bonne idée ! Où allons-nous fêter ça ?"),
        ("A", "Bei mir zu Hause. Lena wird denken, dass wir nur zusammen essen gehen.", "Chez moi. Lena va penser que nous allons seulement dîner ensemble."),
        ("B", "Und wer backt die Torte?", "Et qui fait le gâteau ?"),
        ("A", "Ich backe sie selbst, eine Schokoladentorte mit fünfundzwanzig Kerzen.", "Je le fais moi-même, un gâteau au chocolat avec vingt-cinq bougies."),
        ("B", "Dann bringe ich die Getränke und die Musik mit.", "Alors j'apporte les boissons et la musique."),
        ("A", "Hast du schon ein Geschenk für sie?", "As-tu déjà un cadeau pour elle ?"),
        ("B", "Ja, einen roten Schal. Sie friert im Winter immer.", "Oui, une écharpe rouge. Elle a toujours froid en hiver."),
        ("A", "Perfekt. Wir laden auch ihre Schwester ein. Aber niemand darf Lena etwas verraten!", "Parfait. Nous invitons aussi sa sœur. Mais personne ne doit rien révéler à Lena !"),
        ("B", "Abgemacht, ich sage kein Wort. Mein Mund bleibt zu!", "Entendu, je ne dis pas un mot. Ma bouche reste fermée !"),
    ]),
    ("Une invitation à dîner", [
        ("A", "Haben Sie am Samstag schon etwas vor, Herr Weber?", "Avez-vous déjà quelque chose de prévu samedi, Monsieur Weber ?"),
        ("B", "Am Samstag? Nein, bisher noch nicht. Warum fragen Sie?", "Samedi ? Non, pas encore. Pourquoi demandez-vous ?"),
        ("A", "Meine Frau und ich möchten Sie und Ihre Frau zum Abendessen einladen.", "Ma femme et moi aimerions vous inviter, vous et votre épouse, à dîner."),
        ("B", "Das ist sehr freundlich! Um wie viel Uhr sollen wir kommen?", "C'est très aimable ! À quelle heure devons-nous venir ?"),
        ("A", "Kommen Sie bitte um halb acht, dann essen wir um acht.", "Venez à dix-neuf heures trente, s'il vous plaît, nous mangerons à vingt heures."),
        ("B", "Meine Frau hat leider eine Erdnussallergie. Ist das ein Problem?", "Ma femme a malheureusement une allergie aux arachides. Est-ce un problème ?"),
        ("A", "Kein Problem, ich koche ohne Erdnüsse. Mögen Sie Fisch?", "Pas de problème, je cuisine sans arachides. Aimez-vous le poisson ?"),
        ("B", "Ja, sehr gern, besonders gegrillten Fisch.", "Oui, beaucoup, surtout le poisson grillé."),
        ("A", "Perfekt, dann gibt es Fisch mit Kartoffeln und Salat. Zum Nachtisch gibt es Obst.", "Parfait, alors il y aura du poisson avec des pommes de terre et de la salade. En dessert, des fruits."),
        ("B", "Wunderbar. Wir bringen Blumen und eine Flasche Saft mit. Bis Samstag!", "Merveilleux. Nous apportons des fleurs et une bouteille de jus. À samedi !"),
    ]),
    ("Au cinéma", [
        ("A", "Gibt es den neuen Film auch im Original mit Untertiteln?", "Le nouveau film existe-t-il aussi en version originale sous-titrée ?"),
        ("B", "Ja, aber nur in der Spätvorstellung um zweiundzwanzig Uhr fünfzehn.", "Oui, mais seulement à la séance tardive de vingt-deux heures quinze."),
        ("A", "Das ist ein bisschen spät. Läuft er auch am Nachmittag auf Deutsch?", "C'est un peu tard. Passe-t-il aussi l'après-midi en allemand ?"),
        ("B", "Ja, um sechzehn Uhr, aber dann ist er synchronisiert.", "Oui, à seize heures, mais il est alors doublé."),
        ("A", "Ich verstehe noch nicht alles. Dann nehme ich die Spätvorstellung.", "Je ne comprends pas encore tout. Alors je prends la séance tardive."),
        ("B", "Gut. Wie viele Karten möchten Sie, und welche Reihe?", "Bien. Combien de billets voulez-vous, et quel rang ?"),
        ("A", "Eine Karte, bitte, in der Mitte, nicht zu nah an der Leinwand.", "Un billet, s'il vous plaît, au milieu, pas trop près de l'écran."),
        ("B", "Reihe zehn, Platz acht ist frei. Das kostet neun Euro fünfzig, für Studenten acht Euro.", "Rang dix, la place huit est libre. Cela coûte neuf euros cinquante, huit euros pour les étudiants."),
        ("A", "Ich bin Student. Hier ist mein Ausweis.", "Je suis étudiant. Voici ma carte."),
        ("B", "Dann sind es acht Euro. Wollen Sie dazu noch Popcorn? Das große Menü ist heute günstiger.", "Alors ça fait huit euros. Voulez-vous aussi du pop-corn ? Le grand menu est moins cher aujourd'hui."),
    ]),
    ("Au stade", [
        ("A", "Los, beeil dich, der Anpfiff ist in fünf Minuten!", "Allez, dépêche-toi, le coup d'envoi est dans cinq minutes !"),
        ("B", "Ich komme ja schon! Ich habe meinen Fanschal nicht gefunden.", "J'arrive ! Je n'ai pas trouvé mon écharpe de supporter."),
        ("A", "Egal. Hast du die Tickets? Wir haben Stehplätze in der Kurve.", "Peu importe. As-tu les billets ? Nous avons des places debout dans le virage."),
        ("B", "Hier, beide Tickets. Siehst du, die Spieler laufen schon auf den Rasen!", "Voici, les deux billets. Tu vois, les joueurs entrent déjà sur la pelouse !"),
        ("A", "Unsere Mannschaft spielt heute gegen den Tabellenführer.", "Notre équipe joue aujourd'hui contre le leader du classement."),
        ("B", "Dann wird es schwer. Aber wir haben den besseren Torwart.", "Alors ce sera dur. Mais nous avons le meilleur gardien."),
        ("A", "Foul! Der Schiedsrichter pfeift Elfmeter!", "Faute ! L'arbitre siffle un penalty !"),
        ("B", "Elfmeter für uns! Der Kapitän nimmt Anlauf ... und Tor!", "Penalty pour nous ! Le capitaine prend son élan... et but !"),
        ("A", "Wahnsinn, wir führen! Ich schreie so laut, dass ich kaum noch sprechen kann.", "C'est de la folie, nous menons ! Je crie si fort que je peux à peine parler."),
        ("B", "Ich auch! Morgen sind wir beide heiser.", "Moi aussi ! Demain nous serons tous les deux enroués."),
    ]),
    ("À la plage", [
        ("A", "Schau mal, die rote Flagge! Heute dürfen wir nicht ins Wasser.", "Regarde, le drapeau rouge ! Aujourd'hui nous n'avons pas le droit d'aller dans l'eau."),
        ("B", "Warum nicht? Das Meer sieht doch ganz ruhig aus.", "Pourquoi pas ? La mer a pourtant l'air très calme."),
        ("A", "Die Wellen sind gefährlich, hat der Rettungsschwimmer gesagt. Es gibt starke Strömungen.", "Les vagues sont dangereuses, a dit le maître-nageur. Il y a de forts courants."),
        ("B", "Schade. Dann bauen wir eine Sandburg.", "Dommage. Alors construisons un château de sable."),
        ("A", "Gute Idee. Ich hole Eimer und Schaufel aus der Tasche.", "Bonne idée. Je sors le seau et la pelle du sac."),
        ("B", "Sieh mal, hier liegen so viele Muscheln! Die sammle ich für die Burg.", "Regarde, il y a tellement de coquillages ici ! Je les ramasse pour le château."),
        ("A", "Hast du dich schon eingecremt? Die Sonne ist heute stark.", "T'es-tu déjà mis de la crème ? Le soleil est fort aujourd'hui."),
        ("B", "Ja, vor einer Stunde. Du auch? Dein Rücken ist schon ganz rot.", "Oui, il y a une heure. Et toi ? Ton dos est déjà tout rouge."),
        ("A", "Oh nein, dann gehe ich lieber unter den Sonnenschirm.", "Oh non, alors je vais plutôt sous le parasol."),
        ("B", "Gut. Aber wir müssen schnell sein, sonst kommt die Flut vor der Burg!", "Bien. Mais nous devons faire vite, sinon la marée montante arrive avant le château !"),
    ]),
    ("Le temps qu'il fait", [
        ("A", "Sieh mal aus dem Fenster: Es schneit!", "Regarde par la fenêtre : il neige !"),
        ("B", "Du freust dich ja wie ein Kind! Hast du noch nie Schnee gesehen?", "Tu te réjouis comme un enfant ! N'as-tu jamais vu de neige ?"),
        ("A", "Nein, in Kamerun gibt es keinen Schnee. Ich muss ihn unbedingt anfassen.", "Non, au Cameroun il n'y a pas de neige. Il faut absolument que je la touche."),
        ("B", "Dann zieh dich warm an. Draußen sind es minus drei Grad.", "Alors habille-toi chaudement. Dehors il fait moins trois degrés."),
        ("A", "Minus drei? Brr! Ich habe keine Mütze und keine Handschuhe.", "Moins trois ? Brr ! Je n'ai ni bonnet ni gants."),
        ("B", "Du kannst meine alten nehmen. Und nimm den dicken Schal.", "Tu peux prendre mes vieux. Et prends la grosse écharpe."),
        ("A", "Das ist lieb von dir! Ist es auf den Straßen nicht glatt?", "C'est gentil de ta part ! Les rues ne sont-elles pas glissantes ?"),
        ("B", "Doch, es gibt Glatteis. Geh langsam und mach kleine Schritte.", "Si, il y a du verglas. Marche lentement et fais de petits pas."),
        ("A", "Wie ein Pinguin! Und was machen die Leute im Winter sonst?", "Comme un pingouin ! Et que font les gens d'autre en hiver ?"),
        ("B", "Sie fahren Schlitten und trinken heißen Tee. Du wirst den Winter lieben!", "Ils font de la luge et boivent du thé chaud. Tu vas adorer l'hiver !"),
    ]),
    ("Projets de vacances", [
        ("A", "Wohin sollen wir im Herbst fahren? Ich habe zwei Wochen Urlaub.", "Où devrions-nous aller en automne ? J'ai deux semaines de congé."),
        ("B", "Ich möchte gern nach Berlin fahren. Dort gibt es viele Sehenswürdigkeiten.", "J'aimerais aller à Berlin. Il y a beaucoup de monuments à visiter là-bas."),
        ("A", "Berlin ist teuer. Wo können wir übernachten?", "Berlin est cher. Où pouvons-nous dormir ?"),
        ("B", "In einer Jugendherberge. Dort kostet ein Bett nur zwanzig Euro pro Nacht.", "Dans une auberge de jeunesse. Un lit n'y coûte que vingt euros par nuit."),
        ("A", "Und womit fahren wir? Der Zug ist billiger als das Flugzeug.", "Et avec quoi voyageons-nous ? Le train est moins cher que l'avion."),
        ("B", "Mit dem Zug. Ich habe im Reiseführer gelesen, dass die Fahrt sechs Stunden dauert.", "En train. J'ai lu dans le guide de voyage que le trajet dure six heures."),
        ("A", "Was möchtest du dort unbedingt sehen?", "Qu'est-ce que tu veux absolument voir là-bas ?"),
        ("B", "Das Brandenburger Tor und die Reste der Mauer. Und du?", "La porte de Brandebourg et les vestiges du Mur. Et toi ?"),
        ("A", "Ich will auf den Fernsehturm. Wenn das Wetter schön ist, sieht man die ganze Stadt.", "Je veux monter à la tour de télévision. Quand il fait beau, on voit toute la ville."),
        ("B", "Dann buchen wir morgen die Tickets, und im Oktober geht es los!", "Alors nous réservons les billets demain, et en octobre nous partons !"),
    ]),
    ("Bagages perdus", [
        ("A", "Mein Koffer ist nicht auf dem Gepäckband angekommen.", "Ma valise n'est pas arrivée sur le tapis à bagages."),
        ("B", "Das tut mir leid. Mit welchem Flug sind Sie angekommen?", "Je suis désolé. Avec quel vol êtes-vous arrivé ?"),
        ("A", "Mit dem Flug aus Douala, um sechs Uhr morgens.", "Avec le vol de Douala, à six heures du matin."),
        ("B", "Bitte füllen Sie dieses Formular aus. Beschreiben Sie auch den Inhalt Ihres Koffers.", "Veuillez remplir ce formulaire. Décrivez aussi le contenu de votre valise."),
        ("A", "Es sind Kleidung, Schuhe und ein Laptop darin. Außerdem hängt ein gelber Anhänger am Griff.", "Il y a des vêtements, des chaussures et un ordinateur portable dedans. De plus, une étiquette jaune est accrochée à la poignée."),
        ("B", "Das hilft uns sehr. Wo wohnen Sie in Deutschland?", "Cela nous aide beaucoup. Où logez-vous en Allemagne ?"),
        ("A", "Im Hotel Linde in Frankfurt, bis Sonntag.", "À l'hôtel Linde à Francfort, jusqu'à dimanche."),
        ("B", "Wir liefern den Koffer ins Hotel, sobald wir ihn gefunden haben.", "Nous livrons la valise à l'hôtel dès que nous l'aurons trouvée."),
        ("A", "Und was mache ich bis dahin? Ich habe keine Zahnbürste und keine Kleidung.", "Et que fais-je d'ici là ? Je n'ai ni brosse à dents ni vêtements."),
        ("B", "Wir geben Ihnen ein Notfallpaket und fünfzig Euro für das Nötigste. Spätestens in vierundzwanzig Stunden melden wir uns.", "Nous vous donnons un kit de dépannage et cinquante euros pour le strict nécessaire. Nous vous contactons dans vingt-quatre heures au plus tard."),
    ]),
    ("Objet trouvé", [
        ("A", "Ich habe eine Geldbörse auf der Parkbank gefunden. Was soll ich tun?", "J'ai trouvé un porte-monnaie sur un banc du parc. Que dois-je faire ?"),
        ("B", "Dann sind Sie hier richtig, das ist das Fundbüro. Wo haben Sie sie gefunden?", "Alors vous êtes au bon endroit, ici c'est le bureau des objets trouvés. Où l'avez-vous trouvé ?"),
        ("A", "Im Stadtpark, neben dem Spielplatz, heute Morgen um acht.", "Dans le parc municipal, à côté de l'aire de jeux, ce matin à huit heures."),
        ("B", "Ist Geld drin? Wir müssen den Inhalt gemeinsam zählen.", "Y a-t-il de l'argent dedans ? Nous devons compter le contenu ensemble."),
        ("A", "Ja, etwa vierzig Euro, eine Bankkarte und ein Führerschein.", "Oui, environ quarante euros, une carte bancaire et un permis de conduire."),
        ("B", "Sehr gut, dann finden wir den Besitzer sicher. Der Führerschein hat ja eine Adresse.", "Très bien, alors nous trouverons sûrement le propriétaire. Le permis comporte une adresse."),
        ("A", "Bekommt der Besitzer die Geldbörse sofort?", "Le propriétaire récupère-t-il le porte-monnaie tout de suite ?"),
        ("B", "Wir rufen ihn heute noch an. Er kann sie morgen abholen.", "Nous l'appelons aujourd'hui encore. Il peut venir le chercher demain."),
        ("A", "Gibt es eigentlich einen Finderlohn?", "Y a-t-il d'ailleurs une récompense pour celui qui trouve ?"),
        ("B", "Ja, aber nur, wenn der Besitzer es möchte. Auf jeden Fall war das sehr ehrlich von Ihnen.", "Oui, mais seulement si le propriétaire le souhaite. En tout cas, c'était très honnête de votre part."),
    ]),
    ("Déclarer un vol", [
        ("A", "Mein Fahrrad ist weg! Ich habe es um acht Uhr vor dem Bahnhof angeschlossen.", "Mon vélo a disparu ! Je l'avais attaché à huit heures devant la gare."),
        ("B", "Beruhigen Sie sich bitte. Ich nehme eine Anzeige auf. Wie sieht das Fahrrad aus?", "Calmez-vous, s'il vous plaît. Je prends votre plainte. À quoi ressemble le vélo ?"),
        ("A", "Es ist ein grünes Mountainbike mit einem schwarzen Sattel und einer Klingel.", "C'est un VTT vert avec une selle noire et une sonnette."),
        ("B", "Kennen Sie die Rahmennummer? Sie steht normalerweise unten am Rahmen.", "Connaissez-vous le numéro de cadre ? Il se trouve normalement en bas du cadre."),
        ("A", "Die habe ich zu Hause aufgeschrieben. Ich kann sie morgen bringen.", "Je l'ai notée chez moi. Je peux l'apporter demain."),
        ("B", "Gut. Was für ein Schloss hatten Sie?", "Bien. Quel genre d'antivol aviez-vous ?"),
        ("A", "Ein Kettenschloss. Ich verstehe nicht, wie man das aufbrechen kann!", "Un antivol à chaîne. Je ne comprends pas comment on peut le forcer !"),
        ("B", "Leider kommen solche Fälle oft vor. Waren Sie versichert?", "Malheureusement ce genre de cas arrive souvent. Étiez-vous assuré ?"),
        ("A", "Ja, ich habe eine Hausratversicherung. Brauche ich ein Dokument von Ihnen?", "Oui, j'ai une assurance habitation. Ai-je besoin d'un document de votre part ?"),
        ("B", "Ja, die Anzeige mit der Aktennummer. Hier ist sie. Wir melden uns, wenn wir das Rad finden.", "Oui, la plainte avec le numéro de dossier. La voici. Nous vous contactons si nous retrouvons le vélo."),
    ]),
    ("Chez le coiffeur", [
        ("A", "Wie hätten Sie es heute gern? Wieder wie beim letzten Mal?", "Comment le voulez-vous aujourd'hui ? Comme la dernière fois ?"),
        ("B", "Nein, diesmal an den Seiten etwas kürzer und oben nur ein bisschen.", "Non, cette fois un peu plus court sur les côtés et seulement un petit peu sur le dessus."),
        ("A", "Soll ich den Bart auch trimmen?", "Dois-je aussi tailler la barbe ?"),
        ("B", "Ja, bitte. Aber nicht zu kurz. Meine Frau mag ihn so.", "Oui, s'il vous plaît. Mais pas trop court. Ma femme l'aime ainsi."),
        ("A", "Dann nehme ich nur die Ränder weg. Soll ich den Nacken rasieren?", "Alors je ne retire que les bords. Dois-je raser la nuque ?"),
        ("B", "Ja, mit dem Rasierer, aber vorsichtig. Das letzte Mal hat es gebrannt.", "Oui, au rasoir, mais avec précaution. La dernière fois, ça a brûlé."),
        ("A", "Keine Sorge, ich arbeite langsam. Ist das Wasser warm genug?", "Pas d'inquiétude, je travaille lentement. L'eau est-elle assez chaude ?"),
        ("B", "Ja, es ist perfekt. Hier ist es viel gemütlicher als bei meinem alten Friseur.", "Oui, elle est parfaite. Ici c'est bien plus agréable que chez mon ancien coiffeur."),
        ("A", "So, fertig! Schauen Sie in den Spiegel. Gefällt es Ihnen?", "Voilà, terminé ! Regardez dans le miroir. Cela vous plaît-il ?"),
        ("B", "Wunderbar, ich sehe zehn Jahre jünger aus! Dann zahle ich gern den Preis für zwei Schnitte.", "Merveilleux, j'ai l'air dix ans plus jeune ! Alors je paie volontiers le prix de deux coupes."),
    ]),
    ("À la caisse du supermarché", [
        ("A", "Bitte legen Sie Ihre Sachen auf das Band.", "Posez vos affaires sur le tapis, s'il vous plaît."),
        ("B", "Moment, ich habe noch Pfandflaschen dabei. Kann ich die hier abgeben?", "Un instant, j'ai encore des bouteilles consignées avec moi. Puis-je les rendre ici ?"),
        ("A", "Ja, stellen Sie sie in den Automaten dort drüben. Er druckt Ihnen einen Pfandbon.", "Oui, mettez-les dans la machine là-bas. Elle vous imprime un bon de consigne."),
        ("B", "Gut, hier ist der Bon. Kann ich ihn gleich einlösen?", "Bien, voici le bon. Puis-je l'utiliser tout de suite ?"),
        ("A", "Natürlich. Dann sind es achtzehn Euro sechzig, minus ein Euro fünfzig Pfand: siebzehn Euro zehn.", "Bien sûr. Alors cela fait dix-huit euros soixante, moins un euro cinquante de consigne : dix-sept euros dix."),
        ("B", "Ich habe auch einen Rabattcoupon für Joghurt. Gilt er noch?", "J'ai aussi un coupon de réduction pour des yaourts. Est-il encore valable ?"),
        ("A", "Bis heute, er ist also noch gültig. Ich ziehe zwanzig Cent ab. Wie möchten Sie zahlen?", "Jusqu'à aujourd'hui, donc il est encore valable. Je déduis vingt centimes. Comment voulez-vous payer ?"),
        ("B", "Bar. Ich habe genau zwanzig Euro, das reicht doch?", "En espèces. J'ai exactement vingt euros, cela suffit, non ?"),
        ("A", "Ja, und ich gebe Ihnen drei Euro zehn zurück. Brauchen Sie eine Tüte?", "Oui, et je vous rends trois euros dix. Avez-vous besoin d'un sac ?"),
        ("B", "Nein, ich habe meine Stofftasche dabei. Schönen Feierabend noch!", "Non, j'ai mon sac en tissu avec moi. Bonne fin de journée !"),
    ]),
    ("Commander une pizza", [
        ("A", "Eine Pizza Margherita, bitte, aber ohne Oliven.", "Une pizza Margherita, s'il vous plaît, mais sans olives."),
        ("B", "Kein Problem. Möchten Sie sie hier essen oder zum Mitnehmen?", "Pas de problème. Voulez-vous la manger ici ou à emporter ?"),
        ("A", "Zum Mitnehmen. Gibt es die Pizza auch halb-halb? Meine Tochter mag Salami.", "À emporter. Peut-on avoir la pizza moitié-moitié ? Ma fille aime le salami."),
        ("B", "Ja, halb Margherita, halb Salami. Wollen Sie extra Käse?", "Oui, moitié Margherita, moitié salami. Voulez-vous du fromage en plus ?"),
        ("A", "Nein, aber mit Knoblauchsoße, bitte. Wie viel kostet das?", "Non, mais avec de la sauce à l'ail, s'il vous plaît. Combien cela coûte-t-il ?"),
        ("B", "Neun Euro fünfzig, die Soße kostet fünfzig Cent extra.", "Neuf euros cinquante, la sauce coûte cinquante centimes de plus."),
        ("A", "Okay. Wie lange muss ich warten? Wir haben großen Hunger.", "D'accord. Combien de temps dois-je attendre ? Nous avons très faim."),
        ("B", "Der Ofen ist heiß, es dauert nur zehn Minuten. Setzen Sie sich so lange auf die Bank.", "Le four est chaud, cela ne prend que dix minutes. Asseyez-vous en attendant sur le banc."),
        ("A", "Gut. Haben Sie auch etwas Süßes, zum Beispiel Tiramisu?", "Bien. Avez-vous aussi quelque chose de sucré, par exemple du tiramisu ?"),
        ("B", "Tiramisu haben wir leider nicht, aber frisches Eis. Soll ich Ihnen zwei Kugeln einpacken?", "Du tiramisu, nous n'en avons malheureusement pas, mais de la glace fraîche. Dois-je vous emballer deux boules ?"),
    ]),
    ("Une livraison", [
        ("A", "Lieferservice Hartmann! Sie haben ein Sofa bestellt, richtig?", "Service de livraison Hartmann ! Vous avez commandé un canapé, c'est bien ça ?"),
        ("B", "Ja, genau. Es ist ziemlich groß. Kommt es überhaupt durch die Tür?", "Oui, exactement. Il est assez grand. Passe-t-il seulement par la porte ?"),
        ("A", "Wir probieren es. Wohnen Sie im dritten Stock? Gibt es einen Aufzug?", "Nous essayons. Habitez-vous au troisième étage ? Y a-t-il un ascenseur ?"),
        ("B", "Leider nein, nur eine enge Treppe.", "Malheureusement non, seulement un escalier étroit."),
        ("A", "Dann tragen wir es zu zweit. Bitte machen Sie den Flur frei.", "Alors nous le portons à deux. Dégagez le couloir, s'il vous plaît."),
        ("B", "Sofort, ich räume die Schuhe weg. Das Sofa kommt ins Wohnzimmer, ans Fenster.", "Tout de suite, je range les chaussures. Le canapé va dans le salon, près de la fenêtre."),
        ("A", "Geschafft! Das war knapp, aber es passt.", "Ça y est ! C'était juste, mais ça passe."),
        ("B", "Es sieht toll aus! Nehmen Sie die Folie bitte wieder mit?", "Il est superbe ! Emportez-vous le film plastique, s'il vous plaît ?"),
        ("A", "Klar, die entsorgen wir. Bitte unterschreiben Sie noch den Lieferschein.", "Bien sûr, nous la jetons. Signez encore le bon de livraison, s'il vous plaît."),
        ("B", "Hier, bitte. Jetzt probiere ich es sofort aus, ich setze mich gleich drauf!", "Voici. Maintenant je l'essaie tout de suite, je m'assieds dessus !"),
    ]),
    ("Le wifi à la maison", [
        ("A", "Mein Internet geht seit heute Morgen nicht mehr. Kannst du mir helfen?", "Mon internet ne marche plus depuis ce matin. Peux-tu m'aider ?"),
        ("B", "Klar. Leuchtet an deinem Router das grüne Lämpchen?", "Bien sûr. Le petit voyant vert de ton routeur est-il allumé ?"),
        ("A", "Nein, es blinkt rot. Was bedeutet das?", "Non, il clignote en rouge. Qu'est-ce que ça veut dire ?"),
        ("B", "Das heißt, der Router hat keine Verbindung. Hast du das Kabel kontrolliert?", "Cela veut dire que le routeur n'a pas de connexion. As-tu vérifié le câble ?"),
        ("A", "Ja, das Kabel steckt fest in der Wand. Es sitzt noch richtig.", "Oui, le câble est bien enfoncé dans le mur. Il est encore bien en place."),
        ("B", "Dann zieh den Stecker aus der Steckdose, warte eine Minute und steck ihn wieder ein.", "Alors débranche la prise du secteur, attends une minute et rebranche-la."),
        ("A", "Okay, ich warte ... So, jetzt blinkt es grün. Ist das gut?", "D'accord, j'attends... Voilà, maintenant il clignote en vert. Est-ce bon signe ?"),
        ("B", "Ja, gleich ist es fertig. Dein Handy sollte sich automatisch verbinden.", "Oui, c'est bientôt prêt. Ton téléphone devrait se connecter automatiquement."),
        ("A", "Es funktioniert! Ich kann wieder Videos sehen. Wie hast du das gemacht?", "Ça marche ! Je peux de nouveau regarder des vidéos. Comment as-tu fait ?"),
        ("B", "Das ist ein alter Trick: Ausschalten und wieder einschalten, das hilft fast immer.", "C'est une vieille astuce : éteindre et rallumer, ça aide presque toujours."),
    ]),
    ("Présenter ses parents", [
        ("A", "Willst du meine Eltern sehen? Hier ist ein Foto vom letzten Weihnachtsfest.", "Veux-tu voir mes parents ? Voici une photo du dernier Noël."),
        ("B", "Wie schön! Das ist deine Mutter, oder? Ihr seht euch sehr ähnlich.", "Comme c'est beau ! C'est ta mère, n'est-ce pas ? Vous vous ressemblez beaucoup."),
        ("A", "Ja, sie heißt Marie. Sie arbeitet als Krankenschwester im Krankenhaus.", "Oui, elle s'appelle Marie. Elle travaille comme infirmière à l'hôpital."),
        ("B", "Und dein Vater? Was macht er beruflich?", "Et ton père ? Que fait-il comme métier ?"),
        ("A", "Er ist Lehrer. Er hat dreißig Jahre Mathematik unterrichtet, jetzt ist er in Rente.", "Il est enseignant. Il a enseigné les mathématiques pendant trente ans, maintenant il est à la retraite."),
        ("B", "Das ist ein langes Berufsleben! Wohnen deine Eltern noch in Kamerun?", "C'est une longue vie professionnelle ! Tes parents habitent-ils toujours au Cameroun ?"),
        ("A", "Ja, in Bafoussam, in einem kleinen Haus mit Garten. Sie bauen Gemüse an.", "Oui, à Bafoussam, dans une petite maison avec jardin. Ils cultivent des légumes."),
        ("B", "Besuchen sie dich manchmal in Deutschland?", "Viennent-ils parfois te rendre visite en Allemagne ?"),
        ("A", "Noch nie, aber nächsten Sommer kommen sie zum ersten Mal. Ich habe schon die Tickets gekauft.", "Jamais encore, mais l'été prochain ils viennent pour la première fois. J'ai déjà acheté les billets."),
        ("B", "Das ist toll! Darf ich deine Eltern dann auch kennenlernen?", "C'est génial ! Pourrai-je alors aussi faire la connaissance de tes parents ?"),
    ]),
    ("Acheter un billet de train", [
        ("A", "Bitte, können Sie mir kurz helfen? Ich verstehe den Fahrkartenautomaten nicht.", "S'il vous plaît, pouvez-vous m'aider un instant ? Je ne comprends pas le distributeur de billets."),
        ("B", "Gern. Wohin möchten Sie denn fahren?", "Volontiers. Où voulez-vous donc aller ?"),
        ("A", "Nach Freiburg, morgen früh. Aber es soll möglichst billig sein.", "À Fribourg, demain matin. Mais ça doit être le moins cher possible."),
        ("B", "Dann drücken Sie auf 'Sparpreis'. Der ist günstiger, aber Sie müssen genau diesen Zug nehmen.", "Alors appuyez sur « Sparpreis ». Il est moins cher, mais vous devez prendre exactement ce train."),
        ("A", "Das ist kein Problem. Welche Uhrzeit nehme ich?", "Ce n'est pas un problème. Quelle heure dois-je choisir ?"),
        ("B", "Die Verbindung um 8:05 Uhr ist gut. Sie kommen um 11:30 Uhr an.", "La liaison de 8h05 est bien. Vous arrivez à 11h30."),
        ("A", "Und wie viel kostet das? Ich sehe auf dem Bildschirm einunddreißig Euro.", "Et combien cela coûte-t-il ? Je vois trente et un euros à l'écran."),
        ("B", "Genau. Wollen Sie mit Münzen oder mit Karte zahlen?", "Exactement. Voulez-vous payer avec des pièces ou par carte ?"),
        ("A", "Ich habe nur Scheine. Nimmt der Automat Geldscheine?", "Je n'ai que des billets. Le distributeur accepte-t-il les billets de banque ?"),
        ("B", "Ja, stecken Sie den Schein in den Schlitz rechts. Dann kommt das Ticket unten heraus.", "Oui, glissez le billet dans la fente à droite. Le ticket sort ensuite en bas."),
    ]),
    ("Louer un vélo", [
        ("A", "Hi, habt ihr auch Elektroräder? Ich habe heute einen weiten Weg vor mir.", "Salut, avez-vous aussi des vélos électriques ? J'ai un long trajet à faire aujourd'hui."),
        ("B", "Klar! Wir haben E-Bikes mit einem starken Akku. Wohin soll es denn gehen?", "Bien sûr ! Nous avons des vélos électriques avec une batterie puissante. Où voulez-vous aller ?"),
        ("A", "Zum Schloss Neuenburg, das sind ungefähr fünfundvierzig Kilometer hin und zurück.", "Au château de Neuenburg, cela fait environ quarante-cinq kilomètres aller-retour."),
        ("B", "Das schafft der Akku locker. Er hält bis zu achtzig Kilometer.", "La batterie y arrive sans problème. Elle tient jusqu'à quatre-vingts kilomètres."),
        ("A", "Super! Was kostet ein E-Bike für einen halben Tag?", "Super ! Combien coûte un vélo électrique pour une demi-journée ?"),
        ("B", "Fünfundzwanzig Euro. Dazu kommt eine Kaution von hundert Euro, die Sie am Abend zurückbekommen.", "Vingt-cinq euros. S'y ajoute une caution de cent euros que vous récupérez le soir."),
        ("A", "Gibt es ein Schloss und einen Helm dazu?", "Y a-t-il aussi un antivol et un casque ?"),
        ("B", "Beides ist dabei. Der Helm hängt am Lenker.", "Les deux sont compris. Le casque est accroché au guidon."),
        ("A", "Wie schalte ich die Unterstützung ein?", "Comment activer l'assistance ?"),
        ("B", "Mit dem Knopf links am Lenker. Fahren Sie vorsichtig und vergessen Sie die Pause nicht!", "Avec le bouton à gauche sur le guidon. Roulez prudemment et n'oubliez pas de faire une pause !"),
    ]),
    ("Au camping", [
        ("A", "Kannst du mir kurz helfen? Mein Zelt steht ganz schief.", "Peux-tu m'aider un instant ? Ma tente est complètement de travers."),
        ("B", "Klar, ich komme. Du hast die Heringe nicht tief genug in den Boden geschlagen.", "Bien sûr, j'arrive. Tu n'as pas assez enfoncé les piquets dans le sol."),
        ("A", "Ich habe keinen Hammer dabei. Kann ich deinen benutzen?", "Je n'ai pas de marteau. Puis-je utiliser le tien ?"),
        ("B", "Hier, bitte. Schlag sie schräg in den Boden, dann halten sie besser.", "Tiens. Enfonce-les en biais dans le sol, ils tiendront mieux."),
        ("A", "Jetzt steht es gerade! Und wo kann ich mein Wasser holen?", "Maintenant elle est droite ! Et où puis-je aller chercher de l'eau ?"),
        ("B", "Am Waschhaus, hinter der Rezeption. Das Wasser ist dort Trinkwasser.", "Au bloc sanitaire, derrière la réception. L'eau y est potable."),
        ("A", "Ab wann ist hier Nachtruhe? Ich möchte morgen früh wandern.", "À partir de quand le silence est-il de rigueur ici ? Je voudrais partir en randonnée demain matin."),
        ("B", "Ab zweiundzwanzig Uhr. Dann sind alle Gäste leise.", "À partir de vingt-deux heures. Alors tous les clients font silence."),
        ("A", "Gut. Hoffentlich regnet es heute Nacht nicht.", "Bien. J'espère qu'il ne pleuvra pas cette nuit."),
        ("B", "Der Wetterbericht sagt: trocken. Morgen früh zeige ich dir den Weg zum Aussichtsturm.", "La météo dit : temps sec. Demain matin je te montrerai le chemin vers la tour panoramique."),
    ]),
]

# --- Vocabulaire supplémentaire ---
VOCAB_EXTRA = [
    ("Personnes", "der Mensch", "l'être humain"),
    ("Personnes", "die Person", "la personne"),
    ("Personnes", "der Freund", "l'ami"),
    ("Personnes", "die Freundin", "l'amie"),
    ("Personnes", "der Herr", "le monsieur"),
    ("Personnes", "der Junge", "le garçon"),
    ("Personnes", "das Mädchen", "la fille"),
    ("Personnes", "der Nachbar", "le voisin"),
    ("Personnes", "der Gast", "l'invité"),
    ("Personnes", "der Chef", "le patron"),
    ("Personnes", "der Kollege", "le collègue"),
    ("Personnes", "die Leute", "les gens"),
    ("Personnes", "der Name", "le nom"),
    ("Personnes", "das Baby", "le bébé"),
    ("Famille", "die Eltern", "les parents"),
    ("Famille", "die Geschwister", "les frères et sœurs"),
    ("Famille", "die Großmutter", "la grand-mère"),
    ("Famille", "der Großvater", "le grand-père"),
    ("Famille", "die Oma", "la mamie"),
    ("Famille", "der Opa", "le papi"),
    ("Famille", "der Onkel", "l'oncle"),
    ("Famille", "die Tante", "la tante"),
    ("Famille", "der Cousin", "le cousin"),
    ("Famille", "die Cousine", "la cousine"),
    ("Famille", "der Neffe", "le neveu"),
    ("Famille", "die Nichte", "la nièce"),
    ("Famille", "der Enkel", "le petit-fils"),
    ("Famille", "der Ehemann", "le mari"),
    ("Famille", "die Ehefrau", "l'épouse"),
    ("Corps humain", "der Körper", "le corps"),
    ("Corps humain", "der Kopf", "la tête"),
    ("Corps humain", "das Gesicht", "le visage"),
    ("Corps humain", "das Auge", "l'œil"),
    ("Corps humain", "das Ohr", "l'oreille"),
    ("Corps humain", "die Nase", "le nez"),
    ("Corps humain", "der Mund", "la bouche"),
    ("Corps humain", "der Zahn", "la dent"),
    ("Corps humain", "das Haar", "le cheveu"),
    ("Corps humain", "der Hals", "le cou"),
    ("Corps humain", "der Arm", "le bras"),
    ("Corps humain", "die Hand", "la main"),
    ("Corps humain", "der Finger", "le doigt"),
    ("Corps humain", "das Bein", "la jambe"),
    ("Corps humain", "der Fuß", "le pied"),
    ("Corps humain", "der Bauch", "le ventre"),
    ("Corps humain", "der Rücken", "le dos"),
    ("Corps humain", "das Herz", "le cœur"),
    ("Corps humain", "das Knie", "le genou"),
    ("Maison", "das Fenster", "la fenêtre"),
    ("Maison", "die Tür", "la porte"),
    ("Maison", "der Garten", "le jardin"),
    ("Maison", "das Schlafzimmer", "la chambre à coucher"),
    ("Maison", "das Wohnzimmer", "le salon"),
    ("Maison", "der Balkon", "le balcon"),
    ("Maison", "die Treppe", "l'escalier"),
    ("Maison", "der Boden", "le sol"),
    ("Maison", "die Wand", "le mur"),
    ("Maison", "das Dach", "le toit"),
    ("Maison", "der Keller", "la cave"),
    ("Maison", "der Flur", "le couloir"),
    ("Maison", "die Toilette", "les toilettes"),
    ("Maison", "die Dusche", "la douche"),
    ("Maison", "der Schlüssel", "la clé"),
    ("Maison", "die Miete", "le loyer"),
    ("Meubles et objets", "der Tisch", "la table"),
    ("Meubles et objets", "der Stuhl", "la chaise"),
    ("Meubles et objets", "das Bett", "le lit"),
    ("Meubles et objets", "der Schrank", "l'armoire"),
    ("Meubles et objets", "das Sofa", "le canapé"),
    ("Meubles et objets", "die Lampe", "la lampe"),
    ("Meubles et objets", "der Spiegel", "le miroir"),
    ("Meubles et objets", "der Teppich", "le tapis"),
    ("Meubles et objets", "das Regal", "l'étagère"),
    ("Meubles et objets", "die Tasche", "le sac"),
    ("Meubles et objets", "das Buch", "le livre"),
    ("Meubles et objets", "der Stift", "le stylo"),
    ("Meubles et objets", "das Papier", "le papier"),
    ("Meubles et objets", "die Flasche", "la bouteille"),
    ("Meubles et objets", "das Glas", "le verre"),
    ("Meubles et objets", "die Tasse", "la tasse"),
    ("Meubles et objets", "der Teller", "l'assiette"),
    ("Meubles et objets", "der Löffel", "la cuillère"),
    ("Meubles et objets", "das Messer", "le couteau"),
    ("Meubles et objets", "die Gabel", "la fourchette"),
    ("Meubles et objets", "der Topf", "la casserole"),
    ("Meubles et objets", "der Kühlschrank", "le réfrigérateur"),
    ("Nourriture", "das Essen", "le repas"),
    ("Nourriture", "das Frühstück", "le petit-déjeuner"),
    ("Nourriture", "das Mittagessen", "le déjeuner"),
    ("Nourriture", "das Abendessen", "le dîner"),
    ("Nourriture", "das Fleisch", "la viande"),
    ("Nourriture", "der Fisch", "le poisson"),
    ("Nourriture", "das Hähnchen", "le poulet"),
    ("Nourriture", "das Ei", "l'œuf"),
    ("Nourriture", "der Käse", "le fromage"),
    ("Nourriture", "die Butter", "le beurre"),
    ("Nourriture", "der Reis", "le riz"),
    ("Nourriture", "die Nudeln", "les pâtes"),
    ("Nourriture", "die Suppe", "la soupe"),
    ("Nourriture", "der Salat", "la salade"),
    ("Nourriture", "der Kuchen", "le gâteau"),
    ("Nourriture", "die Pizza", "la pizza"),
    ("Nourriture", "das Salz", "le sel"),
    ("Nourriture", "der Zucker", "le sucre"),
    ("Nourriture", "die Wurst", "la saucisse"),
    ("Nourriture", "das Öl", "l'huile"),
    ("Nourriture", "die Schokolade", "le chocolat"),
    ("Nourriture", "das Eis", "la glace"),
    ("Boissons", "das Getränk", "la boisson"),
    ("Boissons", "die Milch", "le lait"),
    ("Boissons", "der Saft", "le jus"),
    ("Boissons", "der Orangensaft", "le jus d'orange"),
    ("Boissons", "der Apfelsaft", "le jus de pomme"),
    ("Boissons", "der Wein", "le vin"),
    ("Boissons", "die Cola", "le coca"),
    ("Boissons", "die Limonade", "la limonade"),
    ("Boissons", "das Mineralwasser", "l'eau minérale"),
    ("Boissons", "der Kakao", "le cacao"),
    ("Boissons", "der Sekt", "le vin mousseux"),
    ("Boissons", "der Alkohol", "l'alcool"),
    ("Fruits et légumes", "das Obst", "les fruits"),
    ("Fruits et légumes", "das Gemüse", "les légumes"),
    ("Fruits et légumes", "der Apfel", "la pomme"),
    ("Fruits et légumes", "die Banane", "la banane"),
    ("Fruits et légumes", "die Orange", "l'orange"),
    ("Fruits et légumes", "die Birne", "la poire"),
    ("Fruits et légumes", "die Traube", "le raisin"),
    ("Fruits et légumes", "die Erdbeere", "la fraise"),
    ("Fruits et légumes", "die Zitrone", "le citron"),
    ("Fruits et légumes", "die Kirsche", "la cerise"),
    ("Fruits et légumes", "die Tomate", "la tomate"),
    ("Fruits et légumes", "die Kartoffel", "la pomme de terre"),
    ("Fruits et légumes", "die Zwiebel", "l'oignon"),
    ("Fruits et légumes", "die Karotte", "la carotte"),
    ("Fruits et légumes", "die Gurke", "le concombre"),
    ("Fruits et légumes", "der Knoblauch", "l'ail"),
    ("Vêtements", "die Kleidung", "les vêtements"),
    ("Vêtements", "das Hemd", "la chemise"),
    ("Vêtements", "die Bluse", "le chemisier"),
    ("Vêtements", "die Hose", "le pantalon"),
    ("Vêtements", "das Kleid", "la robe"),
    ("Vêtements", "der Rock", "la jupe"),
    ("Vêtements", "die Jacke", "la veste"),
    ("Vêtements", "der Mantel", "le manteau"),
    ("Vêtements", "der Pullover", "le pull"),
    ("Vêtements", "das T-Shirt", "le tee-shirt"),
    ("Vêtements", "der Anzug", "le costume"),
    ("Vêtements", "der Schuh", "la chaussure"),
    ("Vêtements", "die Socke", "la chaussette"),
    ("Vêtements", "die Mütze", "le bonnet"),
    ("Vêtements", "der Hut", "le chapeau"),
    ("Vêtements", "der Schal", "l'écharpe"),
    ("Vêtements", "die Brille", "les lunettes"),
    ("Couleurs", "die Farbe", "la couleur"),
    ("Couleurs", "rot", "rouge"),
    ("Couleurs", "blau", "bleu"),
    ("Couleurs", "grün", "vert"),
    ("Couleurs", "gelb", "jaune"),
    ("Couleurs", "schwarz", "noir"),
    ("Couleurs", "weiß", "blanc"),
    ("Couleurs", "braun", "marron"),
    ("Couleurs", "grau", "gris"),
    ("Couleurs", "orange", "orange"),
    ("Couleurs", "rosa", "rose"),
    ("Couleurs", "lila", "violet"),
    ("Couleurs", "bunt", "multicolore"),
    ("Animaux", "das Tier", "l'animal"),
    ("Animaux", "der Hund", "le chien"),
    ("Animaux", "die Katze", "le chat"),
    ("Animaux", "der Vogel", "l'oiseau"),
    ("Animaux", "das Pferd", "le cheval"),
    ("Animaux", "die Kuh", "la vache"),
    ("Animaux", "das Schwein", "le cochon"),
    ("Animaux", "das Schaf", "le mouton"),
    ("Animaux", "die Ziege", "la chèvre"),
    ("Animaux", "das Huhn", "la poule"),
    ("Animaux", "die Ente", "le canard"),
    ("Animaux", "die Maus", "la souris"),
    ("Animaux", "der Hase", "le lièvre"),
    ("Animaux", "der Affe", "le singe"),
    ("Animaux", "der Löwe", "le lion"),
    ("Animaux", "der Elefant", "l'éléphant"),
    ("Animaux", "der Bär", "l'ours"),
    ("Animaux", "die Schlange", "le serpent"),
    ("Métiers", "der Beruf", "le métier"),
    ("Métiers", "der Arzt", "le médecin"),
    ("Métiers", "die Ärztin", "la femme médecin"),
    ("Métiers", "der Lehrer", "l'enseignant"),
    ("Métiers", "die Lehrerin", "l'enseignante"),
    ("Métiers", "der Koch", "le cuisinier"),
    ("Métiers", "der Fahrer", "le chauffeur"),
    ("Métiers", "der Polizist", "le policier"),
    ("Métiers", "der Verkäufer", "le vendeur"),
    ("Métiers", "der Ingenieur", "l'ingénieur"),
    ("Métiers", "der Bauer", "l'agriculteur"),
    ("Métiers", "der Friseur", "le coiffeur"),
    ("Métiers", "der Kellner", "le serveur"),
    ("Métiers", "der Bäcker", "le boulanger"),
    ("Métiers", "der Schauspieler", "l'acteur"),
    ("École et études", "die Schule", "l'école"),
    ("École et études", "die Universität", "l'université"),
    ("École et études", "die Klasse", "la classe"),
    ("École et études", "der Schüler", "l'élève"),
    ("École et études", "der Student", "l'étudiant"),
    ("École et études", "der Unterricht", "le cours"),
    ("École et études", "die Prüfung", "l'examen"),
    ("École et études", "die Hausaufgabe", "le devoir"),
    ("École et études", "die Frage", "la question"),
    ("École et études", "die Antwort", "la réponse"),
    ("École et études", "die Tafel", "le tableau"),
    ("École et études", "das Heft", "le cahier"),
    ("École et études", "das Wörterbuch", "le dictionnaire"),
    ("École et études", "die Note", "la note"),
    ("École et études", "die Pause", "la pause"),
    ("École et études", "die Sprache", "la langue"),
    ("École et études", "das Wort", "le mot"),
    ("École et études", "der Satz", "la phrase"),
    ("École et études", "die Übung", "l'exercice"),
    ("Travail et bureau", "die Arbeit", "le travail"),
    ("Travail et bureau", "das Büro", "le bureau"),
    ("Travail et bureau", "die Firma", "l'entreprise"),
    ("Travail et bureau", "die Besprechung", "la réunion"),
    ("Travail et bureau", "der Termin", "le rendez-vous"),
    ("Travail et bureau", "das Gehalt", "le salaire"),
    ("Travail et bureau", "der Vertrag", "le contrat"),
    ("Travail et bureau", "die Stelle", "le poste"),
    ("Travail et bureau", "die Bewerbung", "la candidature"),
    ("Travail et bureau", "der Lebenslauf", "le CV"),
    ("Travail et bureau", "die Fabrik", "l'usine"),
    ("Travail et bureau", "die Maschine", "la machine"),
    ("Travail et bureau", "der Feierabend", "la fin de journée de travail"),
    ("Ville et lieux", "die Stadt", "la ville"),
    ("Ville et lieux", "das Dorf", "le village"),
    ("Ville et lieux", "das Land", "le pays"),
    ("Ville et lieux", "die Straße", "la rue"),
    ("Ville et lieux", "der Platz", "la place"),
    ("Ville et lieux", "die Brücke", "le pont"),
    ("Ville et lieux", "der Park", "le parc"),
    ("Ville et lieux", "die Kirche", "l'église"),
    ("Ville et lieux", "die Moschee", "la mosquée"),
    ("Ville et lieux", "das Rathaus", "la mairie"),
    ("Ville et lieux", "die Post", "la poste"),
    ("Ville et lieux", "die Polizei", "la police"),
    ("Ville et lieux", "der Markt", "le marché"),
    ("Ville et lieux", "das Restaurant", "le restaurant"),
    ("Ville et lieux", "das Café", "le café"),
    ("Ville et lieux", "das Kino", "le cinéma"),
    ("Ville et lieux", "das Museum", "le musée"),
    ("Ville et lieux", "die Bibliothek", "la bibliothèque"),
    ("Ville et lieux", "die Ampel", "le feu de signalisation"),
    ("Ville et lieux", "die Ecke", "le coin"),
    ("Transports", "das Auto", "la voiture"),
    ("Transports", "der Bus", "le bus"),
    ("Transports", "der Zug", "le train"),
    ("Transports", "die Bahn", "le chemin de fer"),
    ("Transports", "die U-Bahn", "le métro"),
    ("Transports", "die Straßenbahn", "le tramway"),
    ("Transports", "das Fahrrad", "le vélo"),
    ("Transports", "das Motorrad", "la moto"),
    ("Transports", "das Taxi", "le taxi"),
    ("Transports", "das Flugzeug", "l'avion"),
    ("Transports", "das Schiff", "le bateau"),
    ("Transports", "der Bahnhof", "la gare"),
    ("Transports", "die Haltestelle", "l'arrêt"),
    ("Transports", "der Flughafen", "l'aéroport"),
    ("Transports", "die Fahrkarte", "le billet de transport"),
    ("Transports", "das Gleis", "la voie"),
    ("Transports", "die Autobahn", "l'autoroute"),
    ("Transports", "der Weg", "le chemin"),
    ("Transports", "der Verkehr", "la circulation"),
    ("Voyage et hôtel", "die Reise", "le voyage"),
    ("Voyage et hôtel", "der Urlaub", "les vacances"),
    ("Voyage et hôtel", "das Hotel", "l'hôtel"),
    ("Voyage et hôtel", "die Rezeption", "la réception"),
    ("Voyage et hôtel", "das Einzelzimmer", "la chambre simple"),
    ("Voyage et hôtel", "das Doppelzimmer", "la chambre double"),
    ("Voyage et hôtel", "die Reservierung", "la réservation"),
    ("Voyage et hôtel", "der Koffer", "la valise"),
    ("Voyage et hôtel", "das Gepäck", "les bagages"),
    ("Voyage et hôtel", "der Reisepass", "le passeport"),
    ("Voyage et hôtel", "der Ausweis", "la carte d'identité"),
    ("Voyage et hôtel", "das Visum", "le visa"),
    ("Voyage et hôtel", "die Grenze", "la frontière"),
    ("Voyage et hôtel", "der Tourist", "le touriste"),
    ("Voyage et hôtel", "die Landkarte", "la carte géographique"),
    ("Voyage et hôtel", "der Strand", "la plage"),
    ("Santé", "die Gesundheit", "la santé"),
    ("Santé", "die Krankheit", "la maladie"),
    ("Santé", "das Krankenhaus", "l'hôpital"),
    ("Santé", "die Apotheke", "la pharmacie"),
    ("Santé", "die Praxis", "le cabinet médical"),
    ("Santé", "das Medikament", "le médicament"),
    ("Santé", "die Tablette", "le comprimé"),
    ("Santé", "das Rezept", "l'ordonnance"),
    ("Santé", "das Fieber", "la fièvre"),
    ("Santé", "die Erkältung", "le rhume"),
    ("Santé", "die Grippe", "la grippe"),
    ("Santé", "der Husten", "la toux"),
    ("Santé", "der Schmerz", "la douleur"),
    ("Santé", "der Unfall", "l'accident"),
    ("Santé", "der Notfall", "l'urgence"),
    ("Nature et météo", "die Natur", "la nature"),
    ("Nature et météo", "das Wetter", "le temps qu'il fait"),
    ("Nature et météo", "die Sonne", "le soleil"),
    ("Nature et météo", "der Mond", "la lune"),
    ("Nature et météo", "der Stern", "l'étoile"),
    ("Nature et météo", "der Himmel", "le ciel"),
    ("Nature et météo", "die Wolke", "le nuage"),
    ("Nature et météo", "der Regen", "la pluie"),
    ("Nature et météo", "der Schnee", "la neige"),
    ("Nature et météo", "der Wind", "le vent"),
    ("Nature et météo", "das Gewitter", "l'orage"),
    ("Nature et météo", "die Temperatur", "la température"),
    ("Nature et météo", "der Berg", "la montagne"),
    ("Nature et météo", "der Fluss", "le fleuve"),
    ("Nature et météo", "der See", "le lac"),
    ("Nature et météo", "das Meer", "la mer"),
    ("Nature et météo", "der Wald", "la forêt"),
    ("Nature et météo", "der Baum", "l'arbre"),
    ("Nature et météo", "die Blume", "la fleur"),
    ("Nature et météo", "die Erde", "la terre"),
    ("Nature et météo", "die Welt", "le monde"),
    ("Nature et météo", "die Luft", "l'air"),
    ("Nature et météo", "das Feuer", "le feu"),
    ("Nature et météo", "die Insel", "l'île"),
    ("Temps (jours, mois, saisons)", "der Montag", "lundi"),
    ("Temps (jours, mois, saisons)", "der Dienstag", "mardi"),
    ("Temps (jours, mois, saisons)", "der Mittwoch", "mercredi"),
    ("Temps (jours, mois, saisons)", "der Donnerstag", "jeudi"),
    ("Temps (jours, mois, saisons)", "der Freitag", "vendredi"),
    ("Temps (jours, mois, saisons)", "der Samstag", "samedi"),
    ("Temps (jours, mois, saisons)", "der Sonntag", "dimanche"),
    ("Temps (jours, mois, saisons)", "der Januar", "janvier"),
    ("Temps (jours, mois, saisons)", "der Februar", "février"),
    ("Temps (jours, mois, saisons)", "der März", "mars"),
    ("Temps (jours, mois, saisons)", "der April", "avril"),
    ("Temps (jours, mois, saisons)", "der Mai", "mai"),
    ("Temps (jours, mois, saisons)", "der Juni", "juin"),
    ("Temps (jours, mois, saisons)", "der Juli", "juillet"),
    ("Temps (jours, mois, saisons)", "der August", "août"),
    ("Temps (jours, mois, saisons)", "der September", "septembre"),
    ("Temps (jours, mois, saisons)", "der Oktober", "octobre"),
    ("Temps (jours, mois, saisons)", "der November", "novembre"),
    ("Temps (jours, mois, saisons)", "der Dezember", "décembre"),
    ("Temps (jours, mois, saisons)", "der Frühling", "le printemps"),
    ("Temps (jours, mois, saisons)", "der Sommer", "l'été"),
    ("Temps (jours, mois, saisons)", "der Herbst", "l'automne"),
    ("Temps (jours, mois, saisons)", "der Winter", "l'hiver"),
    ("Temps (jours, mois, saisons)", "der Tag", "le jour"),
    ("Temps (jours, mois, saisons)", "die Woche", "la semaine"),
    ("Temps (jours, mois, saisons)", "das Wochenende", "le week-end"),
    ("Temps (jours, mois, saisons)", "der Monat", "le mois"),
    ("Temps (jours, mois, saisons)", "das Jahr", "l'année"),
    ("Temps (jours, mois, saisons)", "der Morgen", "le matin"),
    ("Temps (jours, mois, saisons)", "der Mittag", "midi"),
    ("Temps (jours, mois, saisons)", "der Nachmittag", "l'après-midi"),
    ("Temps (jours, mois, saisons)", "der Abend", "le soir"),
    ("Temps (jours, mois, saisons)", "die Nacht", "la nuit"),
    ("Temps (jours, mois, saisons)", "die Uhr", "l'heure, la montre"),
    ("Temps (jours, mois, saisons)", "die Stunde", "l'heure"),
    ("Temps (jours, mois, saisons)", "die Minute", "la minute"),
    ("Temps (jours, mois, saisons)", "die Sekunde", "la seconde"),
    ("Temps (jours, mois, saisons)", "die Zeit", "le temps"),
    ("Temps (jours, mois, saisons)", "das Datum", "la date"),
    ("Temps (jours, mois, saisons)", "der Geburtstag", "l'anniversaire"),
    ("Verbes courants", "sein", "être"),
    ("Verbes courants", "haben", "avoir"),
    ("Verbes courants", "werden", "devenir"),
    ("Verbes courants", "machen", "faire"),
    ("Verbes courants", "gehen", "aller"),
    ("Verbes courants", "kommen", "venir"),
    ("Verbes courants", "sehen", "voir"),
    ("Verbes courants", "essen", "manger"),
    ("Verbes courants", "trinken", "boire"),
    ("Verbes courants", "kaufen", "acheter"),
    ("Verbes courants", "wohnen", "habiter"),
    ("Verbes courants", "arbeiten", "travailler"),
    ("Verbes courants", "lernen", "apprendre"),
    ("Verbes courants", "sprechen", "parler"),
    ("Verbes courants", "heißen", "s'appeler"),
    ("Verbes courants", "lesen", "lire"),
    ("Verbes courants", "schreiben", "écrire"),
    ("Verbes courants", "hören", "entendre"),
    ("Verbes courants", "spielen", "jouer"),
    ("Verbes courants", "fahren", "rouler"),
    ("Verbes courants", "nehmen", "prendre"),
    ("Verbes courants", "geben", "donner"),
    ("Verbes courants", "wissen", "savoir"),
    ("Verbes courants", "können", "pouvoir"),
    ("Verbes courants", "müssen", "devoir"),
    ("Verbes courants", "wollen", "vouloir"),
    ("Verbes courants", "möchten", "aimerais"),
    ("Verbes courants", "sagen", "dire"),
    ("Verbes courants", "fragen", "demander"),
    ("Verbes courants", "antworten", "répondre"),
    ("Verbes courants", "schlafen", "dormir"),
    ("Verbes courants", "lieben", "aimer"),
    ("Verbes courants", "mögen", "apprécier"),
    ("Verbes courants", "brauchen", "avoir besoin de"),
    ("Verbes courants", "finden", "trouver"),
    ("Verbes courants", "bleiben", "rester"),
    ("Verbes courants", "helfen", "aider"),
    ("Verbes courants", "öffnen", "ouvrir"),
    ("Verbes courants", "schließen", "fermer"),
    ("Verbes courants", "bezahlen", "payer"),
    ("Verbes courants", "kochen", "cuisiner"),
    ("Verbes courants", "aufstehen", "se lever"),
    ("Verbes courants", "einkaufen", "faire les courses"),
    ("Verbes courants", "anrufen", "téléphoner"),
    ("Verbes courants", "anfangen", "commencer"),
    ("Verbes courants", "aussteigen", "descendre"),
    ("Verbes courants", "einsteigen", "monter"),
    ("Verbes courants", "mitkommen", "venir avec"),
    ("Verbes courants", "ankommen", "arriver"),
    ("Verbes courants", "abfahren", "partir"),
    ("Verbes courants", "verstehen", "comprendre"),
    ("Verbes courants", "laufen", "courir"),
    ("Verbes courants", "tanzen", "danser"),
    ("Verbes courants", "singen", "chanter"),
    ("Verbes courants", "warten", "attendre"),
    ("Verbes courants", "suchen", "chercher"),
    ("Verbes courants", "denken", "penser"),
    ("Verbes courants", "treffen", "rencontrer"),
    ("Verbes courants", "besuchen", "rendre visite"),
    ("Verbes courants", "schwimmen", "nager"),
    ("Verbes courants", "lachen", "rire"),
    ("Adjectifs", "groß", "grand"),
    ("Adjectifs", "klein", "petit"),
    ("Adjectifs", "gut", "bon"),
    ("Adjectifs", "schlecht", "mauvais"),
    ("Adjectifs", "neu", "nouveau"),
    ("Adjectifs", "alt", "vieux"),
    ("Adjectifs", "jung", "jeune"),
    ("Adjectifs", "schön", "beau"),
    ("Adjectifs", "hässlich", "laid"),
    ("Adjectifs", "schnell", "rapide"),
    ("Adjectifs", "langsam", "lent"),
    ("Adjectifs", "teuer", "cher"),
    ("Adjectifs", "billig", "bon marché"),
    ("Adjectifs", "warm", "chaud"),
    ("Adjectifs", "kalt", "froid"),
    ("Adjectifs", "heiß", "brûlant"),
    ("Adjectifs", "lang", "long"),
    ("Adjectifs", "kurz", "court"),
    ("Adjectifs", "dick", "épais"),
    ("Adjectifs", "dünn", "mince"),
    ("Adjectifs", "müde", "fatigué"),
    ("Adjectifs", "krank", "malade"),
    ("Adjectifs", "gesund", "en bonne santé"),
    ("Adjectifs", "glücklich", "heureux"),
    ("Adjectifs", "traurig", "triste"),
    ("Adjectifs", "freundlich", "aimable"),
    ("Adjectifs", "nett", "gentil"),
    ("Adjectifs", "laut", "bruyant"),
    ("Adjectifs", "leise", "silencieux"),
    ("Adjectifs", "leicht", "léger"),
    ("Adjectifs", "schwer", "lourd"),
    ("Adjectifs", "einfach", "simple"),
    ("Adjectifs", "schwierig", "difficile"),
    ("Adjectifs", "richtig", "correct"),
    ("Adjectifs", "falsch", "faux"),
    ("Adjectifs", "hell", "clair"),
    ("Adjectifs", "dunkel", "sombre"),
    ("Adjectifs", "voll", "plein"),
    ("Adjectifs", "leer", "vide"),
    ("Adjectifs", "sauber", "propre"),
    ("Adjectifs", "schmutzig", "sale"),
    ("Adjectifs", "hungrig", "affamé"),
    ("Adjectifs", "durstig", "assoiffé"),
    ("Adjectifs", "fertig", "prêt"),
    ("Adjectifs", "wichtig", "important"),
    ("Adjectifs", "interessant", "intéressant"),
    ("Adjectifs", "langweilig", "ennuyeux"),
    ("Adjectifs", "reich", "riche"),
    ("Adjectifs", "arm", "pauvre"),
    ("Adjectifs", "stark", "fort"),
    ("Loisirs et sport", "der Sport", "le sport"),
    ("Loisirs et sport", "der Fußball", "le football"),
    ("Loisirs et sport", "das Spiel", "le jeu"),
    ("Loisirs et sport", "der Ball", "le ballon"),
    ("Loisirs et sport", "die Mannschaft", "l'équipe"),
    ("Loisirs et sport", "die Musik", "la musique"),
    ("Loisirs et sport", "das Lied", "la chanson"),
    ("Loisirs et sport", "der Film", "le film"),
    ("Loisirs et sport", "das Hobby", "le loisir"),
    ("Loisirs et sport", "die Freizeit", "le temps libre"),
    ("Loisirs et sport", "das Konzert", "le concert"),
    ("Loisirs et sport", "die Party", "la fête entre amis"),
    ("Loisirs et sport", "das Fest", "la fête"),
    ("Loisirs et sport", "die Gitarre", "la guitare"),
    ("Loisirs et sport", "der Spaziergang", "la promenade"),
    ("Loisirs et sport", "das Foto", "la photo"),
    ("Technologie et communication", "das Handy", "le portable"),
    ("Technologie et communication", "der Computer", "l'ordinateur"),
    ("Technologie et communication", "das Internet", "Internet"),
    ("Technologie et communication", "die E-Mail", "le courriel"),
    ("Technologie et communication", "die Nachricht", "le message"),
    ("Technologie et communication", "das Telefon", "le téléphone"),
    ("Technologie et communication", "die Telefonnummer", "le numéro de téléphone"),
    ("Technologie et communication", "die Adresse", "l'adresse"),
    ("Technologie et communication", "der Fernseher", "la télévision"),
    ("Technologie et communication", "das Radio", "la radio"),
    ("Technologie et communication", "der Bildschirm", "l'écran"),
    ("Technologie et communication", "die Tastatur", "le clavier"),
    ("Technologie et communication", "das Passwort", "le mot de passe"),
    ("Technologie et communication", "der Brief", "la lettre"),
    ("Technologie et communication", "die Zeitung", "le journal"),
    ("Technologie et communication", "der Anruf", "l'appel"),
    ("Argent et magasins", "das Geld", "l'argent"),
    ("Argent et magasins", "der Euro", "l'euro"),
    ("Argent et magasins", "der Preis", "le prix"),
    ("Argent et magasins", "die Bank", "la banque"),
    ("Argent et magasins", "die Kasse", "la caisse"),
    ("Argent et magasins", "das Konto", "le compte"),
    ("Argent et magasins", "die Kreditkarte", "la carte de crédit"),
    ("Argent et magasins", "das Geschäft", "le magasin"),
    ("Argent et magasins", "der Supermarkt", "le supermarché"),
    ("Argent et magasins", "die Bäckerei", "la boulangerie"),
    ("Argent et magasins", "die Rechnung", "la facture"),
    ("Argent et magasins", "das Angebot", "l'offre"),
    ("Argent et magasins", "das Kleingeld", "la monnaie"),
    ("Argent et magasins", "das Portemonnaie", "le porte-monnaie"),
    ("Argent et magasins", "die Tüte", "le sac plastique"),
    ("Argent et magasins", "der Einkauf", "l'achat"),
    ("Argent et magasins", "der Kunde", "le client"),
    ("Mots utiles", "hier", "ici"),
    ("Mots utiles", "dort", "là-bas"),
    ("Mots utiles", "heute", "aujourd'hui"),
    ("Mots utiles", "gestern", "hier"),
    ("Mots utiles", "morgen", "demain"),
    ("Mots utiles", "jetzt", "maintenant"),
    ("Mots utiles", "immer", "toujours"),
    ("Mots utiles", "nie", "jamais"),
    ("Mots utiles", "oft", "souvent"),
    ("Mots utiles", "manchmal", "parfois"),
    ("Mots utiles", "auch", "aussi"),
    ("Mots utiles", "aber", "mais"),
    ("Mots utiles", "oder", "ou"),
    ("Mots utiles", "und", "et"),
    ("Mots utiles", "sehr", "très"),
    ("Mots utiles", "viel", "beaucoup"),
    ("Mots utiles", "wenig", "peu"),
    ("Mots utiles", "links", "à gauche"),
    ("Mots utiles", "rechts", "à droite"),
    ("Mots utiles", "geradeaus", "tout droit"),
    ("Mots utiles", "bitte", "s'il vous plaît"),
    ("Mots utiles", "danke", "merci"),
    ("Mots utiles", "ja", "oui"),
    ("Mots utiles", "nein", "non"),
    ("Mots utiles", "vielleicht", "peut-être"),
    ("Mots utiles", "nicht", "ne pas"),
    ("Mots utiles", "mit", "avec"),
    ("Mots utiles", "ohne", "sans"),
    ("Mots utiles", "wo", "où"),
    ("Mots utiles", "was", "quoi"),
    ("Mots utiles", "wer", "qui"),
    ("Mots utiles", "wie", "comment"),
    ("Mots utiles", "wann", "quand"),
    ("Mots utiles", "warum", "pourquoi"),
    ("Mots utiles", "noch", "encore"),
    ("Mots utiles", "schon", "déjà"),
    ("Mots utiles", "nur", "seulement"),
    ("Mots utiles", "dann", "ensuite"),
    ("Mots utiles", "zusammen", "ensemble"),
    ("Mots utiles", "hallo", "bonjour"),
    ("Mots utiles", "tschüss", "salut"),
    ("Mots utiles", "Entschuldigung", "pardon"),
]

# --- Expressions supplémentaires ---
LESSONS_EXTRA = [
    ("Au restaurant", "Ein Tisch für zwei Personen, bitte.", "Une table pour deux personnes, s'il vous plaît."),
    ("Au restaurant", "Die Speisekarte, bitte.", "La carte, s'il vous plaît."),
    ("Au restaurant", "Was empfehlen Sie?", "Que recommandez-vous ?"),
    ("Au restaurant", "Ich möchte bestellen.", "Je voudrais commander."),
    ("Au restaurant", "Ich nehme die Suppe.", "Je prends la soupe."),
    ("Au restaurant", "Haben Sie vegetarische Gerichte?", "Avez-vous des plats végétariens ?"),
    ("Au restaurant", "Ich bin allergisch gegen Nüsse.", "Je suis allergique aux noix."),
    ("Au restaurant", "Noch ein Wasser, bitte.", "Encore une eau, s'il vous plaît."),
    ("Au restaurant", "Das Essen ist kalt.", "Le plat est froid."),
    ("Au restaurant", "Zusammen oder getrennt?", "Ensemble ou séparément ?"),
    ("Au restaurant", "Stimmt so.", "Gardez la monnaie."),
    ("Au restaurant", "Ist hier noch frei?", "Est-ce encore libre ici ?"),
    ("Au restaurant", "Ich hätte gern ein Bier.", "Je voudrais une bière."),
    ("Au restaurant", "Das war sehr lecker.", "C'était très bon."),
    ("À l'hôtel", "Ich habe ein Zimmer reserviert.", "J'ai réservé une chambre."),
    ("À l'hôtel", "Ich möchte einchecken.", "Je voudrais m'enregistrer."),
    ("À l'hôtel", "Ein Einzelzimmer, bitte.", "Une chambre simple, s'il vous plaît."),
    ("À l'hôtel", "Ein Doppelzimmer mit Bad, bitte.", "Une chambre double avec salle de bains, s'il vous plaît."),
    ("À l'hôtel", "Wie viel kostet das Zimmer pro Nacht?", "Combien coûte la chambre par nuit ?"),
    ("À l'hôtel", "Gibt es WLAN im Zimmer?", "Y a-t-il du wifi dans la chambre ?"),
    ("À l'hôtel", "Wie ist das WLAN-Passwort?", "Quel est le mot de passe du wifi ?"),
    ("À l'hôtel", "Die Dusche ist kaputt.", "La douche est cassée."),
    ("À l'hôtel", "Das Zimmer hat keine Heizung.", "La chambre n'a pas de chauffage."),
    ("À l'hôtel", "Ich brauche noch eine Decke.", "J'ai besoin d'une couverture de plus."),
    ("À l'hôtel", "Können Sie ein Taxi rufen?", "Pouvez-vous appeler un taxi ?"),
    ("À l'hôtel", "Ich möchte auschecken.", "Je voudrais libérer la chambre."),
    ("À l'hôtel", "Zimmer 12, bitte.", "Chambre 12, s'il vous plaît."),
    ("Au téléphone", "Hallo, hier spricht Paul.", "Allô, ici Paul."),
    ("Au téléphone", "Mit wem spreche ich?", "À qui ai-je l'honneur ?"),
    ("Au téléphone", "Einen Moment, bitte.", "Un instant, s'il vous plaît."),
    ("Au téléphone", "Ich möchte Herrn Schmidt sprechen.", "Je voudrais parler à Monsieur Schmidt."),
    ("Au téléphone", "Er ist leider nicht da.", "Il n'est malheureusement pas là."),
    ("Au téléphone", "Kann ich eine Nachricht hinterlassen?", "Puis-je laisser un message ?"),
    ("Au téléphone", "Ich rufe später noch einmal an.", "Je rappellerai plus tard."),
    ("Au téléphone", "Rufst du mich bitte zurück?", "Peux-tu me rappeler, s'il te plaît ?"),
    ("Au téléphone", "Ich kann Sie nicht hören.", "Je ne vous entends pas."),
    ("Au téléphone", "Die Verbindung ist schlecht.", "La connexion est mauvaise."),
    ("Au téléphone", "Könnten Sie lauter sprechen?", "Pourriez-vous parler plus fort ?"),
    ("Au téléphone", "Wie ist deine Telefonnummer?", "Quel est ton numéro de téléphone ?"),
    ("Au téléphone", "Mein Akku ist leer.", "Ma batterie est vide."),
    ("Au téléphone", "Danke für Ihren Anruf.", "Merci de votre appel."),
    ("Demander son chemin", "Entschuldigung, wo ist die Post?", "Excusez-moi, où est la poste ?"),
    ("Demander son chemin", "Ist es weit von hier?", "Est-ce loin d'ici ?"),
    ("Demander son chemin", "Gehen Sie geradeaus.", "Allez tout droit."),
    ("Demander son chemin", "Biegen Sie links ab.", "Tournez à gauche."),
    ("Demander son chemin", "Biegen Sie rechts ab.", "Tournez à droite."),
    ("Demander son chemin", "Die erste Straße links.", "La première rue à gauche."),
    ("Demander son chemin", "Es ist neben der Bank.", "C'est à côté de la banque."),
    ("Demander son chemin", "Es ist gegenüber vom Park.", "C'est en face du parc."),
    ("Demander son chemin", "Es ist hinter dem Supermarkt.", "C'est derrière le supermarché."),
    ("Demander son chemin", "Es ist nicht weit.", "Ce n'est pas loin."),
    ("Demander son chemin", "Gehen Sie bis zur Ampel.", "Allez jusqu'au feu."),
    ("Demander son chemin", "Können Sie mir die Straße auf der Karte zeigen?", "Pouvez-vous me montrer la rue sur la carte ?"),
    ("Demander son chemin", "Ich suche die Touristeninformation.", "Je cherche l'office de tourisme."),
    ("Demander son chemin", "Wie komme ich zum Marktplatz?", "Comment aller à la place du marché ?"),
    ("Au travail", "Ich arbeite von neun bis siebzehn Uhr.", "Je travaille de neuf heures à dix-sept heures."),
    ("Au travail", "Ich habe heute Spätschicht.", "Aujourd'hui, je suis de service du soir."),
    ("Au travail", "Ich habe einen Termin mit dem Chef.", "J'ai un rendez-vous avec le patron."),
    ("Au travail", "Mein Kollege ist krank.", "Mon collègue est malade."),
    ("Au travail", "Ich muss eine E-Mail schreiben.", "Je dois écrire un e-mail."),
    ("Au travail", "Wir haben jetzt Pause.", "Nous avons une pause maintenant."),
    ("Au travail", "Ich mache eine Mittagspause.", "Je fais une pause déjeuner."),
    ("Au travail", "Kannst du mir bitte helfen?", "Peux-tu m'aider, s'il te plaît ?"),
    ("Au travail", "Das Meeting beginnt um zehn Uhr.", "La réunion commence à dix heures."),
    ("Au travail", "Ich habe viel zu tun.", "J'ai beaucoup à faire."),
    ("Au travail", "Ich suche eine Arbeit.", "Je cherche du travail."),
    ("Au travail", "Ich habe morgen frei.", "Demain, je suis en congé."),
    ("Au travail", "Der Drucker funktioniert nicht.", "L'imprimante ne fonctionne pas."),
    ("Au travail", "Ich verdiene nicht viel.", "Je ne gagne pas beaucoup."),
    ("À l'école", "Ich gehe zur Schule.", "Je vais à l'école."),
    ("À l'école", "Ich lerne jeden Tag Deutsch.", "J'apprends l'allemand tous les jours."),
    ("À l'école", "Wir haben heute Unterricht.", "Nous avons cours aujourd'hui."),
    ("À l'école", "Wie schreibt man das Wort?", "Comment écrit-on ce mot ?"),
    ("À l'école", "Ich habe meine Hausaufgaben gemacht.", "J'ai fait mes devoirs."),
    ("À l'école", "Ich habe meinen Stift vergessen.", "J'ai oublié mon stylo."),
    ("À l'école", "Leihst du mir deinen Kugelschreiber?", "Me prêtes-tu ton stylo ?"),
    ("À l'école", "Öffnet das Buch auf Seite zehn.", "Ouvrez le livre à la page dix."),
    ("À l'école", "Die Prüfung ist morgen.", "L'examen est demain."),
    ("À l'école", "Das Wort kenne ich nicht.", "Je ne connais pas ce mot."),
    ("À l'école", "Darf ich bitte hinausgehen?", "Puis-je sortir, s'il vous plaît ?"),
    ("À l'école", "Hören Sie bitte zu.", "Écoutez, s'il vous plaît."),
    ("À l'école", "Mein Lieblingsfach ist Mathe.", "Ma matière préférée est les maths."),
    ("Loisirs", "Was machst du in deiner Freizeit?", "Que fais-tu pendant ton temps libre ?"),
    ("Loisirs", "Ich spiele gern Fußball.", "J'aime jouer au football."),
    ("Loisirs", "Ich lese gern Bücher.", "J'aime lire des livres."),
    ("Loisirs", "Ich tanze sehr gern.", "J'aime beaucoup danser."),
    ("Loisirs", "Ich koche gern mit Freunden.", "J'aime cuisiner avec des amis."),
    ("Loisirs", "Ich gehe oft spazieren.", "Je vais souvent me promener."),
    ("Loisirs", "Hast du ein Hobby?", "As-tu un loisir ?"),
    ("Loisirs", "Ich schwimme jeden Samstag.", "Je nage tous les samedis."),
    ("Loisirs", "Ich sehe gern Filme.", "J'aime regarder des films."),
    ("Loisirs", "Spielst du ein Instrument?", "Joues-tu d'un instrument ?"),
    ("Loisirs", "Ich fahre gern Fahrrad.", "J'aime faire du vélo."),
    ("Loisirs", "Lass uns Karten spielen!", "Jouons aux cartes !"),
    ("Loisirs", "Am Wochenende gehe ich ins Kino.", "Le week-end, je vais au cinéma."),
    ("Voyage", "Ich mache Urlaub in Deutschland.", "Je passe mes vacances en Allemagne."),
    ("Voyage", "Hier ist mein Reisepass.", "Voici mon passeport."),
    ("Voyage", "Ich brauche ein Visum.", "J'ai besoin d'un visa."),
    ("Voyage", "Ich bin Tourist.", "Je suis touriste."),
    ("Voyage", "Ich bleibe eine Woche.", "Je reste une semaine."),
    ("Voyage", "Wo ist die Passkontrolle?", "Où est le contrôle des passeports ?"),
    ("Voyage", "Ich habe nichts zu verzollen.", "Je n'ai rien à déclarer."),
    ("Voyage", "Mein Flug geht um acht Uhr.", "Mon vol part à huit heures."),
    ("Voyage", "Wo ist mein Gepäck?", "Où sont mes bagages ?"),
    ("Voyage", "Ich möchte ein Foto machen.", "Je voudrais prendre une photo."),
    ("Voyage", "Können Sie ein Foto von uns machen?", "Pouvez-vous nous prendre en photo ?"),
    ("Voyage", "Ich möchte die Stadt besichtigen.", "Je voudrais visiter la ville."),
    ("Voyage", "Wann öffnet das Museum?", "Quand ouvre le musée ?"),
    ("Voyage", "Ich brauche einen Stadtplan.", "J'ai besoin d'un plan de la ville."),
    ("Au marché", "Ich möchte ein Kilo Tomaten.", "Je voudrais un kilo de tomates."),
    ("Au marché", "Was kosten die Äpfel?", "Combien coûtent les pommes ?"),
    ("Au marché", "Sind die Bananen frisch?", "Les bananes sont-elles fraîches ?"),
    ("Au marché", "Ich nehme ein halbes Pfund Käse.", "Je prends une demi-livre de fromage."),
    ("Au marché", "Geben Sie mir bitte drei Orangen.", "Donnez-moi trois oranges, s'il vous plaît."),
    ("Au marché", "Haben Sie auch Mangos?", "Avez-vous aussi des mangues ?"),
    ("Au marché", "Das ist alles, danke.", "C'est tout, merci."),
    ("Au marché", "Darf es sonst noch etwas sein?", "Désirez-vous autre chose ?"),
    ("Au marché", "Das Gemüse sieht gut aus.", "Les légumes ont l'air bons."),
    ("Au marché", "Ich brauche eine Tüte.", "J'ai besoin d'un sac."),
    ("Au marché", "Haben Sie Kleingeld?", "Avez-vous de la monnaie ?"),
    ("Au marché", "Ein Stück Brot, bitte.", "Un morceau de pain, s'il vous plaît."),
    ("Au marché", "Der Markt ist samstags geöffnet.", "Le marché est ouvert le samedi."),
    ("Au marché", "Kann ich probieren?", "Puis-je goûter ?"),
    ("Rendez-vous", "Ich möchte einen Termin vereinbaren.", "Je voudrais prendre rendez-vous."),
    ("Rendez-vous", "Haben Sie morgen Zeit?", "Avez-vous le temps demain ?"),
    ("Rendez-vous", "Passt Ihnen Montag um zehn Uhr?", "Lundi à dix heures vous convient-il ?"),
    ("Rendez-vous", "Leider habe ich da keine Zeit.", "Malheureusement, je n'ai pas le temps à ce moment-là."),
    ("Rendez-vous", "Können wir den Termin verschieben?", "Pouvons-nous reporter le rendez-vous ?"),
    ("Rendez-vous", "Ich muss den Termin absagen.", "Je dois annuler le rendez-vous."),
    ("Rendez-vous", "Wir treffen uns um drei Uhr.", "Nous nous retrouvons à quinze heures."),
    ("Rendez-vous", "Ich warte vor dem Eingang.", "J'attends devant l'entrée."),
    ("Rendez-vous", "Ich bin gleich da.", "J'arrive tout de suite."),
    ("Rendez-vous", "Entschuldigung, ich bin spät dran.", "Désolé, je suis en retard."),
    ("Rendez-vous", "Bis morgen!", "À demain !"),
    ("Rendez-vous", "Ich habe einen Termin beim Zahnarzt.", "J'ai un rendez-vous chez le dentiste."),
    ("Sentiments", "Ich bin glücklich.", "Je suis heureux."),
    ("Sentiments", "Ich bin traurig.", "Je suis triste."),
    ("Sentiments", "Ich bin sehr nervös.", "Je suis très nerveux."),
    ("Sentiments", "Ich habe Angst.", "J'ai peur."),
    ("Sentiments", "Ich bin sauer.", "Je suis en colère."),
    ("Sentiments", "Ich freue mich auf morgen.", "Je me réjouis de demain."),
    ("Sentiments", "Mir ist langweilig.", "Je m'ennuie."),
    ("Sentiments", "Mir ist kalt.", "J'ai froid."),
    ("Sentiments", "Mir ist heiß.", "J'ai chaud."),
    ("Sentiments", "Ich bin stolz auf dich.", "Je suis fier de toi."),
    ("Sentiments", "Ich vermisse dich.", "Tu me manques."),
    ("Sentiments", "Ich liebe dich.", "Je t'aime."),
    ("Sentiments", "Das macht mir Spaß.", "Cela me plaît."),
    ("Invitations", "Möchtest du mit mir essen gehen?", "Veux-tu aller manger avec moi ?"),
    ("Invitations", "Ich lade dich zum Essen ein.", "Je t'invite à manger."),
    ("Invitations", "Hast du Lust auf einen Kaffee?", "As-tu envie d'un café ?"),
    ("Invitations", "Kommst du zu meiner Party?", "Viens-tu à ma fête ?"),
    ("Invitations", "Gern, ich komme.", "Avec plaisir, je viens."),
    ("Invitations", "Leider kann ich nicht kommen.", "Malheureusement, je ne peux pas venir."),
    ("Invitations", "Vielen Dank für die Einladung.", "Merci beaucoup pour l'invitation."),
    ("Invitations", "Wir feiern am Samstag.", "Nous faisons la fête samedi."),
    ("Invitations", "Bringst du etwas zu trinken mit?", "Apportes-tu quelque chose à boire ?"),
    ("Invitations", "Herzlichen Glückwunsch zum Geburtstag!", "Joyeux anniversaire !"),
    ("Invitations", "Kommen Sie doch herein.", "Entrez donc."),
    ("Invitations", "Fühl dich wie zu Hause.", "Fais comme chez toi."),
    ("Invitations", "Setzen Sie sich bitte.", "Asseyez-vous, s'il vous plaît."),
    ("Invitations", "Was für eine schöne Überraschung!", "Quelle belle surprise !"),
    ("Excuses", "Entschuldigung!", "Excusez-moi !"),
    ("Excuses", "Es tut mir leid.", "Je suis désolé."),
    ("Excuses", "Das war mein Fehler.", "C'était mon erreur."),
    ("Excuses", "Das macht nichts.", "Ce n'est pas grave."),
    ("Excuses", "Kein Problem.", "Pas de problème."),
    ("Excuses", "Ich habe es nicht gewusst.", "Je ne le savais pas."),
    ("Excuses", "Verzeihung, darf ich vorbei?", "Pardon, puis-je passer ?"),
    ("Excuses", "Entschuldigen Sie die Störung.", "Excusez-moi de vous déranger."),
    ("Excuses", "Das tut mir wirklich leid.", "Je suis vraiment désolé."),
    ("Excuses", "Keine Sorge.", "Ne vous inquiétez pas."),
    ("Excuses", "Ich komme leider zu spät.", "J'arrive malheureusement en retard."),
    ("Excuses", "Das habe ich nicht gewollt.", "Je ne l'ai pas voulu."),
    ("Excuses", "Schon gut.", "C'est bon."),
    ("Banque et poste", "Ich möchte ein Konto eröffnen.", "Je voudrais ouvrir un compte."),
    ("Banque et poste", "Ich möchte Geld wechseln.", "Je voudrais changer de l'argent."),
    ("Banque et poste", "Wie ist der Wechselkurs?", "Quel est le taux de change ?"),
    ("Banque et poste", "Ich möchte Geld überweisen.", "Je voudrais faire un virement."),
    ("Banque et poste", "Ich habe meine PIN vergessen.", "J'ai oublié mon code PIN."),
    ("Banque et poste", "Meine Karte ist gesperrt.", "Ma carte est bloquée."),
    ("Banque et poste", "Wie hoch sind die Gebühren?", "À combien s'élèvent les frais ?"),
    ("Banque et poste", "Ich möchte einen Brief nach Kamerun schicken.", "Je voudrais envoyer une lettre au Cameroun."),
    ("Banque et poste", "Eine Briefmarke, bitte.", "Un timbre, s'il vous plaît."),
    ("Banque et poste", "Wie lange dauert das Paket?", "Combien de temps le colis met-il ?"),
    ("Banque et poste", "Ich möchte ein Paket abholen.", "Je voudrais retirer un colis."),
    ("Banque et poste", "Wo kann ich unterschreiben?", "Où puis-je signer ?"),
    ("Banque et poste", "Hier ist mein Ausweis.", "Voici ma pièce d'identité."),
    ("Banque et poste", "Die Bank schließt um vier Uhr.", "La banque ferme à seize heures."),
    ("Internet et technologie", "Hast du WLAN?", "As-tu du wifi ?"),
    ("Internet et technologie", "Das Internet ist langsam.", "Internet est lent."),
    ("Internet et technologie", "Ich habe kein Netz.", "Je n'ai pas de réseau."),
    ("Internet et technologie", "Ich muss mein Handy aufladen.", "Je dois recharger mon portable."),
    ("Internet et technologie", "Hast du ein Ladekabel?", "As-tu un câble de chargeur ?"),
    ("Internet et technologie", "Schick mir bitte eine Nachricht.", "Envoie-moi un message, s'il te plaît."),
    ("Internet et technologie", "Wie ist deine E-Mail-Adresse?", "Quelle est ton adresse e-mail ?"),
    ("Internet et technologie", "Mein Computer startet nicht.", "Mon ordinateur ne démarre pas."),
    ("Internet et technologie", "Ich habe die Datei gespeichert.", "J'ai enregistré le fichier."),
    ("Internet et technologie", "Wir machen einen Videoanruf.", "Nous faisons un appel vidéo."),
    ("Internet et technologie", "Ich lade die App herunter.", "Je télécharge l'application."),
    ("Internet et technologie", "Das Passwort ist falsch.", "Le mot de passe est faux."),
    ("Internet et technologie", "Mach bitte das Handy aus.", "Éteins ton portable, s'il te plaît."),
    ("Internet et technologie", "Ich schreibe dir auf WhatsApp.", "Je t'écris sur WhatsApp."),
    ("Santé", "Ich habe Husten.", "Je tousse."),
    ("Santé", "Wo ist die nächste Apotheke?", "Où est la pharmacie la plus proche ?"),
    ("Santé", "Ich brauche Tabletten gegen Schmerzen.", "J'ai besoin de comprimés contre la douleur."),
    ("Santé", "Der Arzt hat heute geöffnet.", "Le médecin est ouvert aujourd'hui."),
    ("Santé", "Mir ist schlecht.", "J'ai mal au cœur."),
    ("Santé", "Ich muss mich ausruhen.", "Je dois me reposer."),
    ("Santé", "Trinken Sie viel Wasser.", "Buvez beaucoup d'eau."),
    ("Urgences", "Ich brauche sofort Hilfe!", "J'ai besoin d'aide tout de suite !"),
    ("Urgences", "Es gab einen Unfall.", "Il y a eu un accident."),
    ("Urgences", "Mein Portemonnaie wurde gestohlen.", "On m'a volé mon portefeuille."),
    ("Urgences", "Feuer!", "Au feu !"),
    ("Urgences", "Ich habe mich verletzt.", "Je me suis blessé."),
    ("Politesse", "Gern geschehen.", "Avec plaisir."),
    ("Politesse", "Bitte sehr.", "Voilà, je vous en prie."),
    ("Politesse", "Viel Glück!", "Bonne chance !"),
    ("Politesse", "Schönen Tag noch!", "Bonne journée !"),
    ("Politesse", "Schönes Wochenende!", "Bon week-end !"),
    ("Météo", "Heute scheint die Sonne.", "Aujourd'hui, il y a du soleil."),
    ("Météo", "Es ist sehr heiß heute.", "Il fait très chaud aujourd'hui."),
    ("Météo", "Morgen schneit es.", "Demain, il neige."),
    ("Météo", "Es ist windig und kalt.", "Il y a du vent et il fait froid."),
    ("Temps", "Ich stehe um sechs Uhr auf.", "Je me lève à six heures."),
    ("Temps", "Es ist halb drei.", "Il est deux heures et demie."),
    ("Temps", "Ich habe keine Zeit.", "Je n'ai pas le temps."),
    ("Temps", "Ich komme morgen früh.", "Je viens demain matin."),
    ("Temps", "Heute ist Montag.", "Aujourd'hui, c'est lundi."),
    ("Maison", "Ich wohne in einer kleinen Wohnung.", "J'habite dans un petit appartement."),
    ("Maison", "Ich muss die Wäsche waschen.", "Je dois faire la lessive."),
    ("Maison", "Kannst du bitte den Müll rausbringen?", "Peux-tu sortir les poubelles, s'il te plaît ?"),
    ("Famille", "Mein Vater arbeitet als Fahrer.", "Mon père travaille comme chauffeur."),
    ("Famille", "Meine Mutter kocht sehr gut.", "Ma mère cuisine très bien."),
    ("Famille", "Hast du Geschwister?", "As-tu des frères et sœurs ?"),
]

def seed_lessons(cursor):
    data = [
        ("Salutations", "Hallo!", "Salut ! / Bonjour !"), ("Salutations", "Guten Morgen!", "Bonjour ! (le matin)"),
        ("Salutations", "Guten Tag!", "Bonjour !"), ("Salutations", "Guten Abend!", "Bonsoir !"),
        ("Salutations", "Gute Nacht!", "Bonne nuit !"), ("Salutations", "Wie geht es dir?", "Comment vas-tu ?"),
        ("Salutations", "Wie geht es Ihnen?", "Comment allez-vous ?"), ("Salutations", "Mir geht es gut, danke.", "Je vais bien, merci."),
        ("Salutations", "Und dir?", "Et toi ?"), ("Salutations", "Auf Wiedersehen!", "Au revoir !"),
        ("Se présenter", "Ich heiße Davy.", "Je m'appelle Davy."), ("Se présenter", "Wie heißt du?", "Comment t'appelles-tu ?"),
        ("Se présenter", "Mein Name ist Davy.", "Mon nom est Davy."), ("Se présenter", "Freut mich.", "Enchanté."),
        ("Se présenter", "Ich komme aus Kamerun.", "Je viens du Cameroun."), ("Se présenter", "Woher kommst du?", "D'où viens-tu ?"),
        ("Se présenter", "Ich wohne in Paris.", "J'habite à Paris."), ("Se présenter", "Wo wohnst du?", "Où habites-tu ?"),
        ("Se présenter", "Ich bin neu hier.", "Je suis nouveau ici."),
        ("Comprendre", "Ich verstehe.", "Je comprends."), ("Comprendre", "Ich verstehe nicht.", "Je ne comprends pas."),
        ("Comprendre", "Bitte wiederholen Sie.", "Veuillez répéter, s'il vous plaît."), ("Comprendre", "Langsamer, bitte.", "Plus lentement, s'il vous plaît."),
        ("Questions", "Was ist das?", "Qu'est-ce que c'est ?"), ("Questions", "Wer ist das?", "Qui est-ce ?"),
        ("Questions", "Wo ist die Toilette?", "Où sont les toilettes ?"), ("Questions", "Wann kommst du?", "Quand viens-tu ?"),
        ("Questions", "Warum?", "Pourquoi ?"), ("Questions", "Wie viel kostet das?", "Combien cela coûte-t-il ?"),
        ("Questions", "Wie spät ist es?", "Quelle heure est-il ?"),
        ("Famille", "Das ist meine Familie.", "Voici ma famille."), ("Famille", "Das ist mein Bruder.", "Voici mon frère."),
        ("Famille", "Das ist meine Schwester.", "Voici ma sœur."), ("Famille", "Ich habe zwei Kinder.", "J'ai deux enfants."),
        ("Maison", "Ich bin zu Hause.", "Je suis à la maison."), ("Maison", "Komm bitte herein.", "Entre, s'il te plaît."),
        ("Maison", "Wo ist mein Schlüssel?", "Où est ma clé ?"),
        ("Repas", "Ich habe Hunger.", "J'ai faim."), ("Repas", "Ich habe Durst.", "J'ai soif."),
        ("Repas", "Guten Appetit!", "Bon appétit !"), ("Repas", "Die Rechnung, bitte.", "L'addition, s'il vous plaît."),
        ("Transport", "Wo ist der Bahnhof?", "Où est la gare ?"), ("Transport", "Wann fährt der Zug?", "Quand part le train ?"),
        ("Transport", "Eine Fahrkarte nach Berlin, bitte.", "Un billet pour Berlin, s'il vous plaît."),
        ("Achats", "Wie viel kostet das?", "Combien ça coûte ?"), ("Achats", "Das ist zu teuer.", "C'est trop cher."),
        ("Achats", "Wo ist die Kasse?", "Où est la caisse ?"),
        ("Temps", "Es ist acht Uhr.", "Il est huit heures."), ("Temps", "Heute habe ich Zeit.", "Aujourd'hui, j'ai le temps."),
        ("Météo", "Wie ist das Wetter heute?", "Quel temps fait-il aujourd'hui ?"), ("Météo", "Es regnet.", "Il pleut."),
        ("Santé", "Ich bin krank.", "Je suis malade."), ("Santé", "Ich brauche einen Arzt.", "J'ai besoin d'un médecin."),
        ("Urgences", "Hilfe!", "Au secours !"), ("Urgences", "Rufen Sie die Polizei!", "Appelez la police !"),
        ("Politesse", "Danke!", "Merci !"), ("Politesse", "Bitte schön.", "Je vous en prie."),
    ]
    _sync_lessons(cursor, data)

def seed_wfragen(cursor):
    data = [
        ("W-Fragen", "Wer ist das?", "Qui est-ce ?"), ("W-Fragen", "Wer kommt heute?", "Qui vient aujourd'hui ?"),
        ("W-Fragen", "Wer hat das gesagt?", "Qui a dit ça ?"), ("W-Fragen", "Wer wohnt hier?", "Qui habite ici ?"),
        ("W-Fragen", "Wer sind Sie?", "Qui êtes-vous ?"), ("W-Fragen", "Wer ist dein Lehrer?", "Qui est ton professeur ?"),
        ("W-Fragen", "Wer hat Zeit?", "Qui a le temps ?"), ("W-Fragen", "Wer ist müde?", "Qui est fatigué ?"),
        ("W-Fragen", "Wer kocht das Essen?", "Qui cuisine le repas ?"), ("W-Fragen", "Wer arbeitet hier?", "Qui travaille ici ?"),
        ("W-Fragen", "Was machst du?", "Que fais-tu ?"), ("W-Fragen", "Was ist das?", "Qu'est-ce que c'est ?"),
        ("W-Fragen", "Was möchtest du trinken?", "Que veux-tu boire ?"), ("W-Fragen", "Was kostet das Buch?", "Combien coûte le livre ?"),
        ("W-Fragen", "Was ist dein Name?", "Quel est ton nom ?"), ("W-Fragen", "Was isst du gern?", "Qu'est-ce que tu aimes manger ?"),
        ("W-Fragen", "Was machst du heute Abend?", "Que fais-tu ce soir ?"), ("W-Fragen", "Was ist passiert?", "Que s'est-il passé ?"),
        ("W-Fragen", "Was brauchst du?", "De quoi as-tu besoin ?"), ("W-Fragen", "Was hast du gesagt?", "Qu'as-tu dit ?"),
        ("W-Fragen", "Wo wohnst du?", "Où habites-tu ?"), ("W-Fragen", "Wo ist die Toilette?", "Où sont les toilettes ?"),
        ("W-Fragen", "Wo ist der Bahnhof?", "Où est la gare ?"), ("W-Fragen", "Wo ist das Hotel?", "Où est l'hôtel ?"),
        ("W-Fragen", "Wo arbeitest du?", "Où travailles-tu ?"), ("W-Fragen", "Wo ist mein Schlüssel?", "Où est ma clé ?"),
        ("W-Fragen", "Wo kann ich parken?", "Où puis-je me garer ?"), ("W-Fragen", "Wo ist die Apotheke?", "Où est la pharmacie ?"),
        ("W-Fragen", "Wo ist der Supermarkt?", "Où est le supermarché ?"), ("W-Fragen", "Wo treffen wir uns?", "Où nous retrouvons-nous ?"),
        ("W-Fragen", "Wann kommst du?", "Quand viens-tu ?"), ("W-Fragen", "Wann fängt der Kurs an?", "Quand commence le cours ?"),
        ("W-Fragen", "Wann fährt der Zug?", "Quand part le train ?"), ("W-Fragen", "Wann hast du Geburtstag?", "Quand est ton anniversaire ?"),
        ("W-Fragen", "Wann ist das Frühstück?", "À quelle heure est le petit-déjeuner ?"), ("W-Fragen", "Wann gehen wir ins Kino?", "Quand allons-nous au cinéma ?"),
        ("W-Fragen", "Wann bist du fertig?", "Quand as-tu fini ?"), ("W-Fragen", "Wann öffnet das Geschäft?", "Quand ouvre le magasin ?"),
        ("W-Fragen", "Wann kommt der Bus?", "Quand arrive le bus ?"), ("W-Fragen", "Wann sehen wir uns wieder?", "Quand nous reverrons-nous ?"),
        ("W-Fragen", "Warum lernst du Deutsch?", "Pourquoi apprends-tu l'allemand ?"), ("W-Fragen", "Warum kommst du zu spät?", "Pourquoi viens-tu en retard ?"),
        ("W-Fragen", "Warum ist das so teuer?", "Pourquoi est-ce si cher ?"), ("W-Fragen", "Warum bist du traurig?", "Pourquoi es-tu triste ?"),
        ("W-Fragen", "Warum lachst du?", "Pourquoi ris-tu ?"), ("W-Fragen", "Warum nicht?", "Pourquoi pas ?"),
        ("W-Fragen", "Warum ist die Tür zu?", "Pourquoi la porte est-elle fermée ?"), ("W-Fragen", "Warum hast du keine Zeit?", "Pourquoi n'as-tu pas le temps ?"),
        ("W-Fragen", "Warum fragst du?", "Pourquoi demandes-tu ?"), ("W-Fragen", "Warum arbeitest du heute?", "Pourquoi travailles-tu aujourd'hui ?"),
        ("W-Fragen", "Wie heißt du?", "Comment t'appelles-tu ?"), ("W-Fragen", "Wie geht es dir?", "Comment vas-tu ?"),
        ("W-Fragen", "Wie alt bist du?", "Quel âge as-tu ?"), ("W-Fragen", "Wie kommt ich zum Bahnhof?", "Comment aller à la gare ?"),
        ("W-Fragen", "Wie viel kostet das?", "Combien cela coûte-t-il ?"), ("W-Fragen", "Wie spät ist es?", "Quelle heure est-il ?"),
        ("W-Fragen", "Wie ist das Wetter?", "Quel temps fait-il ?"), ("W-Fragen", "Wie schreibt man das?", "Comment cela s'écrit-il ?"),
        ("W-Fragen", "Wie sagt man das auf Deutsch?", "Comment dit-on cela en allemand ?"), ("W-Fragen", "Wie lange dauert das?", "Combien de temps cela dure-t-il ?"),
        ("W-Fragen", "Woher kommst du?", "D'où viens-tu ?"), ("W-Fragen", "Woher hast du das?", "D'où tiens-tu cela ?"),
        ("W-Fragen", "Woher weißt du das?", "Comment le sais-tu ?"), ("W-Fragen", "Woher kommt dieser Zug?", "D'où vient ce train ?"),
        ("W-Fragen", "Woher sind Sie?", "D'où êtes-vous ?"), ("W-Fragen", "Woher hast du dieses Buch?", "D'où as-tu ce livre ?"),
        ("W-Fragen", "Woher kommt der Lärm?", "D'où vient le bruit ?"), ("W-Fragen", "Woher kennen wir uns?", "D'où nous connaissons-nous ?"),
        ("W-Fragen", "Woher kommt das Wasser?", "D'où vient l'eau ?"), ("W-Fragen", "Woher hast du die Information?", "D'où tiens-tu l'information ?"),
        ("W-Fragen", "Wohin gehst du?", "Où vas-tu ?"), ("W-Fragen", "Wohin fährst du im Urlaub?", "Où vas-tu en vacances ?"),
        ("W-Fragen", "Wohin legst du das Buch?", "Où mets-tu le livre ?"), ("W-Fragen", "Wohin gehen wir heute Abend?", "Où allons-nous ce soir ?"),
        ("W-Fragen", "Wohin fährt dieser Bus?", "Où va ce bus ?"), ("W-Fragen", "Wohin hast du es gelegt?", "Où l'as-tu mis ?"),
        ("W-Fragen", "Wohin läufst du?", "Où cours-tu ?"), ("W-Fragen", "Wohin stellst du die Flasche?", "Où poses-tu la bouteille ?"),
        ("W-Fragen", "Wohin reist du?", "Où voyages-tu ?"), ("W-Fragen", "Wohin geht ihr?", "Où allez-vous ?"),
    ]
    
    _sync_lessons(cursor, data)

def seed_vocab(cursor):
    vocab = [
        ("Personnes", "der Mann", "l'homme"), ("Personnes", "die Frau", "la femme"), ("Personnes", "das Kind", "l'enfant"),
        ("Personnes", "die Familie", "la famille"), ("Personnes", "der Vater", "le père"), ("Personnes", "die Mutter", "la mère"),
        ("Personnes", "der Sohn", "le fils"), ("Personnes", "die Tochter", "la fille"), ("Personnes", "der Bruder", "le frère"),
        ("Personnes", "die Schwester", "la sœur"),
        ("Maison", "das Haus", "la maison"), ("Maison", "die Wohnung", "l'appartement"), ("Maison", "das Zimmer", "la pièce / la chambre"),
        ("Maison", "die Küche", "la cuisine"), ("Maison", "das Bad", "la salle de bains"),
        ("Nourriture", "das Wasser", "l'eau"), ("Nourriture", "das Brot", "le pain"), ("Nourriture", "der Kaffee", "le café"),
        ("Nourriture", "der Tee", "le thé"), ("Nourriture", "das Bier", "la bière"),
    ]
    _sync_vocab(cursor, vocab)

def seed_lessons_extra(cursor):
    _sync_lessons(cursor, LESSONS_EXTRA)

def seed_vocab_extra(cursor):
    _sync_vocab(cursor, VOCAB_EXTRA)

def seed_dialogues(cursor):
    """Synchronise les dialogues : un seul exemplaire de chaque, ceux qui ne sont plus dans le code
    (anciens dialogues, doublons) sont supprimés."""
    wanted = {title: json.dumps([{"spk": s, "de": d, "fr": f} for s, d, f in lines])
              for title, lines in DIALOGUES_DATA}
    seen = set()
    for did, title, lj in cursor.execute("SELECT id, title, lines_json FROM dialogues ORDER BY id").fetchall():
        if title not in wanted or title in seen:
            cursor.execute("DELETE FROM dialogues WHERE id=?", (did,))
            continue
        seen.add(title)
        if lj != wanted[title]:
            cursor.execute("UPDATE dialogues SET lines_json=? WHERE id=?", (wanted[title], did))
    for title, _lines in DIALOGUES_DATA:
        if title not in seen:
            cursor.execute("INSERT INTO dialogues(title, lines_json) VALUES(?, ?)", (title, wanted[title]))

def seed_numbers(cursor):
    # Les anciennes lignes contenaient des chiffres (« 5 » en français comme en allemand) : on les
    # remplace par de vrais mots, puis on ajoute ceux qui manquent.
    for i, (de, fr) in enumerate(NUMBER_WORDS):
        cursor.execute("UPDATE vocab SET german=?, french=? WHERE category='Nombres' AND german=?",
                       (de, fr, str(i)))
    existing = {r[0] for r in cursor.execute("SELECT german FROM vocab WHERE category='Nombres'").fetchall()}
    for de, fr in NUMBER_WORDS:
        if de not in existing:
            cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", ("Nombres", de, fr))


# =========================================================
# SEED "APPRENDRE À PARLER" (260 phrases complètes)
# =========================================================
SPEAK_PHRASES_DATA = [
    ("Se présenter et parler de soi", [
        ("Je m'appelle Marie.", "Ich heiße Marie."),
        ("Je viens du Cameroun.", "Ich komme aus Kamerun."),
        ("J'habite à Douala.", "Ich wohne in Douala."),
        ("J'ai 25 ans.", "Ich bin 25 Jahre alt."),
        ("Je suis étudiant.", "Ich bin Student."),
        ("Je suis étudiante.", "Ich bin Studentin."),
        ("Je travaille dans un bureau.", "Ich arbeite in einem Büro."),
        ("Je parle français et anglais.", "Ich spreche Französisch und Englisch."),
        ("J'apprends l'allemand.", "Ich lerne Deutsch."),
        ("Ma langue maternelle est le français.", "Meine Muttersprache ist Französisch."),
        ("Je suis célibataire.", "Ich bin ledig."),
        ("Je suis marié(e).", "Ich bin verheiratet."),
        ("J'ai deux frères.", "Ich habe zwei Brüder."),
        ("J'ai une sœur.", "Ich habe eine Schwester."),
        ("Je suis nouveau ici.", "Ich bin neu hier."),
        ("Je suis content de te rencontrer.", "Ich freue mich, dich kennenzulernen."),
        ("Comment tu t'appelles ?", "Wie heißt du?"),
        ("Quel âge as-tu ?", "Wie alt bist du?"),
        ("D'où viens-tu ?", "Woher kommst du?"),
        ("Où habites-tu ?", "Wo wohnst du?"),
    ]),
    ("La famille et les amis", [
        ("Voici ma mère.", "Das ist meine Mutter."),
        ("Voici mon père.", "Das ist mein Vater."),
        ("J'ai deux enfants.", "Ich habe zwei Kinder."),
        ("Mon fils a cinq ans.", "Mein Sohn ist fünf Jahre alt."),
        ("Ma fille est à l'école.", "Meine Tochter ist in der Schule."),
        ("Mon frère habite à Berlin.", "Mein Bruder wohnt in Berlin."),
        ("Ma sœur est médecin.", "Meine Schwester ist Ärztin."),
        ("Mes parents habitent ici.", "Meine Eltern wohnen hier."),
        ("J'ai un cousin en Allemagne.", "Ich habe einen Cousin in Deutschland."),
        ("Ma famille est grande.", "Meine Familie ist groß."),
        ("Mon ami s'appelle Paul.", "Mein Freund heißt Paul."),
        ("Mon amie s'appelle Anna.", "Meine Freundin heißt Anna."),
        ("Nous sommes une famille de quatre.", "Wir sind eine Familie von vier."),
        ("Tu es marié(e) ?", "Bist du verheiratet?"),
        ("Je rends visite à mes grands-parents.", "Ich besuche meine Großeltern."),
        ("Mon oncle est médecin.", "Mein Onkel ist Arzt."),
        ("Ma tante est professeure.", "Meine Tante ist Lehrerin."),
        ("Nous sommes amis depuis longtemps.", "Wir sind seit langem Freunde."),
        ("Mes grands-parents habitent à la campagne.", "Meine Großeltern wohnen auf dem Land."),
        ("J'aime ma famille.", "Ich liebe meine Familie."),
    ]),
    ("La maison et le logement", [
        ("J'habite dans une maison.", "Ich wohne in einem Haus."),
        ("J'habite dans un appartement.", "Ich wohne in einer Wohnung."),
        ("Ma chambre est grande.", "Mein Zimmer ist groß."),
        ("La cuisine est propre.", "Die Küche ist sauber."),
        ("La salle de bains est petite.", "Das Bad ist klein."),
        ("J'ai un jardin.", "Ich habe einen Garten."),
        ("La clé est sur la table.", "Der Schlüssel ist auf dem Tisch."),
        ("Ferme la porte, s'il te plaît.", "Mach die Tür zu, bitte."),
        ("Ouvre la fenêtre, s'il te plaît.", "Öffne bitte das Fenster."),
        ("Allume la lumière, s'il te plaît.", "Mach bitte das Licht an."),
        ("Éteins la lumière, s'il te plaît.", "Mach bitte das Licht aus."),
        ("Le loyer est trop élevé.", "Die Miete ist zu hoch."),
        ("J'ai besoin d'une serviette.", "Ich brauche ein Handtuch."),
        ("Où est la télévision ?", "Wo ist der Fernseher?"),
        ("Le lit est très confortable.", "Das Bett ist sehr bequem."),
        ("Je nettoie ma chambre.", "Ich räume mein Zimmer auf."),
        ("Le frigo est vide.", "Der Kühlschrank ist leer."),
        ("Le canapé est dans le salon.", "Das Sofa ist im Wohnzimmer."),
        ("Il y a une table dans la cuisine.", "Es gibt einen Tisch in der Küche."),
        ("Ma maison est belle.", "Mein Haus ist schön."),
    ]),
    ("Les repas et la nourriture", [
        ("J'ai faim.", "Ich habe Hunger."),
        ("J'ai soif.", "Ich habe Durst."),
        ("Je mange du pain.", "Ich esse Brot."),
        ("Je bois de l'eau.", "Ich trinke Wasser."),
        ("Je bois du café.", "Ich trinke Kaffee."),
        ("Je mange du riz.", "Ich esse Reis."),
        ("Je n'aime pas le poisson.", "Ich mag keinen Fisch."),
        ("J'aime les fruits.", "Ich mag Obst."),
        ("Le repas est prêt.", "Das Essen ist fertig."),
        ("C'est très bon.", "Das schmeckt sehr gut."),
        ("Je mange à midi.", "Ich esse zu Mittag."),
        ("Je mange le soir à 19h.", "Ich esse am Abend um 19 Uhr."),
        ("Je prépare le dîner.", "Ich koche das Abendessen."),
        ("Je prends le petit-déjeuner.", "Ich frühstücke."),
        ("Passe-moi le sel, s'il te plaît.", "Gib mir bitte das Salz."),
        ("Passe-moi le poivre, s'il te plaît.", "Gib mir bitte den Pfeffer."),
        ("Un verre d'eau, s'il te plaît.", "Ein Glas Wasser, bitte."),
        ("Je suis végétarien.", "Ich bin Vegetarier."),
        ("Je mange de la viande.", "Ich esse Fleisch."),
        ("Le gâteau est délicieux.", "Der Kuchen ist lecker."),
    ]),
    ("Les achats et l'argent", [
        ("Je voudrais acheter ceci.", "Ich möchte das kaufen."),
        ("Combien cela coûte-t-il ?", "Wie viel kostet das?"),
        ("C'est trop cher.", "Das ist zu teuer."),
        ("Avez-vous quelque chose de moins cher ?", "Haben Sie etwas Günstigeres?"),
        ("Où est la caisse ?", "Wo ist die Kasse?"),
        ("Je peux payer par carte ?", "Kann ich mit Karte bezahlen?"),
        ("Je paie en espèces.", "Ich zahle bar."),
        ("Je prends cela.", "Ich nehme das."),
        ("Je cherche une chemise.", "Ich suche ein Hemd."),
        ("Je peux essayer cela ?", "Kann ich das anprobieren?"),
        ("Quelle taille faites-vous ?", "Welche Größe haben Sie?"),
        ("Cela me va bien.", "Das passt mir gut."),
        ("C'est trop grand.", "Das ist zu groß."),
        ("C'est trop petit.", "Das ist zu klein."),
        ("Puis-je avoir un reçu ?", "Kann ich eine Quittung bekommen?"),
        ("J'ai besoin d'argent.", "Ich brauche Geld."),
        ("Où est le distributeur ?", "Wo ist der Geldautomat?"),
        ("Je voudrais retirer de l'argent.", "Ich möchte Geld abheben."),
        ("La carte ne fonctionne pas.", "Die Karte funktioniert nicht."),
        ("C'est gratuit.", "Das ist kostenlos."),
    ]),
    ("Le transport et les déplacements", [
        ("Où est l'arrêt de bus ?", "Wo ist die Bushaltestelle?"),
        ("Quand part le train ?", "Wann fährt der Zug?"),
        ("Un billet pour Berlin, s'il vous plaît.", "Eine Fahrkarte nach Berlin, bitte."),
        ("Où dois-je changer ?", "Wo muss ich umsteigen?"),
        ("Le train a du retard.", "Der Zug hat Verspätung."),
        ("Je prends le bus.", "Ich nehme den Bus."),
        ("Je vais à pied.", "Ich gehe zu Fuß."),
        ("De quel quai part le train ?", "Von welchem Gleis fährt der Zug?"),
        ("Quand arrive le bus ?", "Wann kommt der Bus an?"),
        ("Un aller-retour, s'il vous plaît.", "Einmal hin und zurück, bitte."),
        ("Cette place est-elle libre ?", "Ist dieser Platz frei?"),
        ("Où est l'aéroport ?", "Wo ist der Flughafen?"),
        ("Je voudrais un taxi.", "Ich brauche ein Taxi."),
        ("Combien de temps dure le trajet ?", "Wie lange dauert die Fahrt?"),
        ("Je me suis perdu.", "Ich habe mich verlaufen."),
        ("Je prends le métro.", "Ich nehme die U-Bahn."),
        ("Le bus arrive dans 5 minutes.", "Der Bus kommt in 5 Minuten."),
        ("Où est la gare ?", "Wo ist der Bahnhof?"),
        ("Je vais à l'hôtel.", "Ich gehe zum Hotel."),
        ("Je voyage en train.", "Ich reise mit dem Zug."),
    ]),
    ("À l'hôtel et en voyage", [
        ("J'ai une réservation.", "Ich habe eine Reservierung."),
        ("Je voudrais réserver une chambre.", "Ich möchte ein Zimmer buchen."),
        ("Avez-vous une chambre libre ?", "Haben Sie ein freies Zimmer?"),
        ("À quelle heure est le petit-déjeuner ?", "Wann ist das Frühstück?"),
        ("Où est ma chambre ?", "Wo ist mein Zimmer?"),
        ("La clé ne fonctionne pas.", "Der Schlüssel funktioniert nicht."),
        ("Je reste deux nuits.", "Ich bleibe zwei Nächte."),
        ("Je peux partir plus tard ?", "Kann ich später auschecken?"),
        ("Où puis-je laisser mes bagages ?", "Wo kann ich mein Gepäck lassen?"),
        ("Bon voyage !", "Gute Reise!"),
        ("Le petit-déjeuner est inclus.", "Das Frühstück ist inklusive."),
        ("La chambre est très propre.", "Das Zimmer ist sehr sauber."),
        ("Où est l'ascenseur ?", "Wo ist der Aufzug?"),
        ("Quand dois-je libérer la chambre ?", "Wann muss ich auschecken?"),
        ("J'ai perdu mon passeport.", "Ich habe meinen Pass verloren."),
        ("Ma valise est lourde.", "Mein Koffer ist schwer."),
        ("Je voudrais annuler ma réservation.", "Ich möchte meine Reservierung stornieren."),
        ("Je suis en vacances.", "Ich bin im Urlaub."),
        ("Je voyage pour le travail.", "Ich reise geschäftlich."),
        ("Je visite la ville.", "Ich besichtige die Stadt."),
    ]),
    ("La santé et les urgences", [
        ("Je suis malade.", "Ich bin krank."),
        ("J'ai mal à la tête.", "Ich habe Kopfschmerzen."),
        ("J'ai mal au ventre.", "Ich habe Bauchschmerzen."),
        ("J'ai de la fièvre.", "Ich habe Fieber."),
        ("J'ai mal à la gorge.", "Ich habe Halsschmerzen."),
        ("J'ai besoin d'un médecin.", "Ich brauche einen Arzt."),
        ("Je dois aller chez le médecin.", "Ich muss zum Arzt gehen."),
        ("J'ai besoin d'un rendez-vous.", "Ich brauche einen Termin."),
        ("Où est la pharmacie ?", "Wo ist die Apotheke?"),
        ("J'ai besoin de médicaments.", "Ich brauche Medikamente."),
        ("Au secours !", "Hilfe!"),
        ("Appelez la police !", "Rufen Sie die Polizei!"),
        ("Appelez une ambulance !", "Rufen Sie einen Krankenwagen!"),
        ("C'est une urgence.", "Es ist ein Notfall."),
        ("Je ne me sens pas bien.", "Ich fühle mich nicht gut."),
        ("J'ai mal au dos.", "Mein Rücken tut weh."),
        ("Je suis fatigué.", "Ich bin müde."),
        ("Je me sens mieux.", "Ich fühle mich besser."),
        ("Bon rétablissement !", "Gute Besserung!"),
        ("Je prends ce médicament.", "Ich nehme dieses Medikament."),
    ]),
    ("Le travail et les études", [
        ("Quelle est ta profession ?", "Was machst du beruflich?"),
        ("Je travaille dans un hôpital.", "Ich arbeite in einem Krankenhaus."),
        ("Je suis en première année.", "Ich bin im ersten Studienjahr."),
        ("Je suis à l'école.", "Ich bin in der Schule."),
        ("Je suis un cours d'allemand.", "Ich besuche einen Deutschkurs."),
        ("Le professeur explique la grammaire.", "Der Lehrer erklärt die Grammatik."),
        ("J'ai un examen demain.", "Ich habe morgen eine Prüfung."),
        ("J'ai une question.", "Ich habe eine Frage."),
        ("Je fais mes devoirs.", "Ich mache meine Hausaufgaben."),
        ("J'ai terminé.", "Ich bin fertig."),
        ("Je cherche du travail.", "Ich suche Arbeit."),
        ("Mon chef est sympa.", "Mein Chef ist nett."),
        ("Je suis en congé aujourd'hui.", "Ich habe heute frei."),
        ("J'ai beaucoup de travail.", "Ich habe viel Arbeit."),
        ("Le travail commence à huit heures.", "Die Arbeit beginnt um acht Uhr."),
        ("J'apprends l'allemand pour travailler.", "Ich lerne Deutsch, weil ich arbeiten möchte."),
        ("Je voudrais travailler à Berlin.", "Ich möchte in Berlin arbeiten."),
        ("L'école commence en septembre.", "Die Schule beginnt im September."),
        ("J'étudie à l'université.", "Ich studiere an der Universität."),
        ("Je lis un livre en allemand.", "Ich lese ein Buch auf Deutsch."),
    ]),
    ("Les loisirs et le temps libre", [
        ("Qu'aimes-tu faire ?", "Was machst du gern?"),
        ("J'aime écouter de la musique.", "Ich höre gern Musik."),
        ("J'aime lire.", "Ich lese gern."),
        ("Je joue au football.", "Ich spiele Fußball."),
        ("Je regarde un film.", "Ich sehe einen Film."),
        ("Je vais au cinéma.", "Ich gehe ins Kino."),
        ("Je vais me promener.", "Ich gehe spazieren."),
        ("Je danse.", "Ich tanze."),
        ("Je chante.", "Ich singe."),
        ("Je nage.", "Ich schwimme."),
        ("Je fais du sport.", "Ich mache Sport."),
        ("Je joue de la guitare.", "Ich spiele Gitarre."),
        ("C'est amusant.", "Das macht Spaß."),
        ("Je n'ai pas envie.", "Ich habe keine Lust."),
        ("Allons au parc.", "Lass uns in den Park gehen."),
        ("Tu veux venir avec moi ?", "Möchtest du mitkommen?"),
        ("Avec plaisir !", "Gern!"),
        ("Malheureusement, je ne peux pas.", "Leider kann ich nicht."),
        ("Le week-end, je suis libre.", "Am Wochenende habe ich frei."),
        ("J'ai un passe-temps.", "Ich habe ein Hobby."),
    ]),
    ("La météo et les saisons", [
        ("Quel temps fait-il aujourd'hui ?", "Wie ist das Wetter heute?"),
        ("Il fait beau.", "Das Wetter ist schön."),
        ("Il pleut.", "Es regnet."),
        ("Il neige.", "Es schneit."),
        ("Il fait froid.", "Es ist kalt."),
        ("Il fait chaud.", "Es ist heiß."),
        ("Il y a du vent.", "Es ist windig."),
        ("Le soleil brille.", "Die Sonne scheint."),
        ("Il fait 20 degrés.", "Es sind 20 Grad."),
        ("Prends un parapluie.", "Nimm einen Regenschirm mit."),
        ("En hiver, il fait très froid.", "Im Winter ist es sehr kalt."),
        ("En été, il fait chaud.", "Im Sommer ist es heiß."),
        ("C'est le printemps.", "Es ist Frühling."),
        ("C'est l'automne.", "Es ist Herbst."),
        ("Il fait mauvais.", "Das Wetter ist schlecht."),
        ("Le ciel est bleu.", "Der Himmel ist blau."),
        ("Il y a des nuages.", "Es gibt Wolken."),
        ("Le temps est agréable.", "Das Wetter ist angenehm."),
        ("Il fait nuit.", "Es ist Nacht."),
        ("Demain, il fera beau.", "Morgen wird das Wetter schön."),
    ]),
    ("Les rendez-vous et les projets", [
        ("Qu'est-ce qu'on fait demain ?", "Was machen wir morgen?"),
        ("J'ai un plan.", "Ich habe einen Plan."),
        ("Je voudrais étudier aujourd'hui.", "Ich möchte heute lernen."),
        ("Je t'appellerai.", "Ich werde dich anrufen."),
        ("Peut-être demain.", "Vielleicht morgen."),
        ("On fera cela plus tard.", "Das machen wir später."),
        ("J'ai du temps ce week-end.", "Ich habe am Wochenende Zeit."),
        ("Quand es-tu libre ?", "Wann hast du frei?"),
        ("Je viendrai volontiers.", "Ich komme gern mit."),
        ("À la semaine prochaine !", "Bis nächste Woche!"),
        ("On se retrouve à 18h.", "Wir treffen uns um 18 Uhr."),
        ("Je suis en retard.", "Ich bin zu spät."),
        ("Je suis à l'heure.", "Ich bin pünktlich."),
        ("Je viendrai plus tard.", "Ich komme später."),
        ("On se voit demain.", "Wir sehen uns morgen."),
        ("Je suis occupé aujourd'hui.", "Ich bin heute beschäftigt."),
        ("J'ai un rendez-vous.", "Ich habe einen Termin."),
        ("On se retrouve devant le cinéma.", "Wir treffen uns vor dem Kino."),
        ("À tout à l'heure !", "Bis später!"),
        ("À bientôt !", "Bis bald!"),
    ]),
    ("Les questions et la conversation courante", [
        ("Comment vas-tu ?", "Wie geht es dir?"),
        ("Je vais bien, merci.", "Mir geht es gut, danke."),
        ("Et toi ?", "Und dir?"),
        ("Comment t'appelles-tu ?", "Wie heißt du?"),
        ("Je suis d'accord.", "Ich bin einverstanden."),
        ("Tu as raison.", "Du hast recht."),
        ("Que fais-tu ?", "Was machst du?"),
        ("Pourquoi ?", "Warum?"),
        ("Quand ?", "Wann?"),
        ("Où ?", "Wo?"),
        ("Qui ?", "Wer?"),
        ("Quoi ?", "Was?"),
        ("Comment ?", "Wie?"),
        ("Combien ?", "Wie viel?"),
        ("Peux-tu m'aider ?", "Kannst du mir helfen?"),
        ("Je ne comprends pas.", "Ich verstehe nicht."),
        ("Peux-tu répéter ?", "Kannst du das wiederholen?"),
        ("Plus lentement, s'il te plaît.", "Langsamer, bitte."),
        ("Comment dit-on cela en allemand ?", "Wie sagt man das auf Deutsch?"),
        ("Merci beaucoup.", "Vielen Dank."),
    ]),
]

def seed_speak_phrases(cursor):
    for theme_order, (theme, items) in enumerate(SPEAK_PHRASES_DATA, start=1):
        for fr, de in items:
            cursor.execute(
                "INSERT OR IGNORE INTO speak_phrases(theme, theme_order, fr, de) VALUES(?,?,?,?)",
                (theme, theme_order, fr, de)
            )

# =========================================================
# SEED "LES ESSENTIELS A1"
# =========================================================
ESSENTIALS_DATA = [
    (1, "Les pronoms personnels (sujets)",
     "Je = ich\nTu = du\nIl = er\nElle = sie\nIl/Elle (neutre) = es\nNous = wir\nVous (pluriel) = ihr\nVous (poli) = Sie\nIls/Elles = sie",
     "Le pronom sujet se place toujours avant le verbe. 'Sie' avec majuscule = vouvoiement ; 'sie' minuscule = ils/elles."),
    (2, "Le verbe 'sein' (être) au présent",
     "Je suis = ich bin\nTu es = du bist\nIl/Elle est = er/sie/es ist\nNous sommes = wir sind\nVous êtes = ihr seid\nIls/Elles sont = sie sind\nVous êtes (poli) = Sie sind",
     "'sein' est irrégulier : il faut le mémoriser. C'est le verbe le plus utilisé en allemand."),
    (3, "Le verbe 'haben' (avoir) au présent",
     "J'ai = ich habe\nTu as = du hast\nIl/Elle a = er/sie/es hat\nNous avons = wir haben\nVous avez = ihr habt\nIls/Elles ont = sie haben\nVous avez (poli) = Sie haben",
     "'haben' est aussi irrégulier au singulier (du hast, er hat). Indispensable pour parler."),
    (4, "Les articles définis (le, la, les)",
     "Masculin : der (ex: der Mann)\nFéminin : die (ex: die Frau)\nNeutre : das (ex: das Kind)\nPluriel : die (ex: die Kinder)",
     "Il existe 3 genres en allemand. Le pluriel est toujours 'die'. Apprends toujours le nom AVEC son article."),
    (5, "Les articles indéfinis (un, une)",
     "Masculin : ein (ex: ein Mann)\nFéminin : eine (ex: eine Frau)\nNeutre : ein (ex: ein Kind)",
     "'ein' pour masculin et neutre, 'eine' pour féminin. Pas d'article indéfini au pluriel."),
    (6, "Les questions avec 'W'",
     "Qui ? = Wer?\nQuoi ? = Was?\nOù ? = Wo?\nD'où ? = Woher?\nOù (direction) ? = Wohin?\nQuand ? = Wann?\nPourquoi ? = Warum?\nComment ? = Wie?",
     "Les mots interrogatifs allemands commencent presque tous par W. Le verbe reste en 2e position."),
    (7, "La négation",
     "Ne pas = nicht (ex: Ich verstehe nicht. = Je ne comprends pas.)\nAucun/Ne...pas de = kein/keine (ex: Ich habe keinen Hund. = Je n'ai pas de chien.)",
     "'nicht' nie un verbe/adj. 'kein' nie un nom (avec l'article indéfini)."),
    (8, "Les verbes réguliers au présent (exemple: lernen)",
     "J'apprends = ich lerne\nTu apprends = du lernst\nIl/Elle apprend = er/sie/es lernt\nNous apprenons = wir lernen\nVous apprenez = ihr lernt\nIls/Elles apprennent = sie lernen",
     "Verbes réguliers : radical + terminaison (-e, -st, -t, -en, -t, -en)."), 
    (9, "Les verbes irréguliers courants au présent",
     "Je parle = ich spreche\nTu parles = du sprichst\nIl/Elle parle = er/sie/es spricht\nJe lis = ich lese\nTu lis = du liest\nIl/Elle lit = er/sie/es liest\nJe mange = ich esse\nTu manges = du isst\nIl/Elle mange = er/sie/es isst",
     "Certains verbes changent de voyelle au singulier (e → i, a → ä). Il faut les mémoriser."),
    (10, "Les nombres de 0 à 20",
     "0 null, 1 eins, 2 zwei, 3 drei, 4 vier, 5 fünf, 6 sechs, 7 sieben, 8 acht, 9 neun, 10 zehn, 11 elf, 12 zwölf, 13 dreizehn, 14 vierzehn, 15 fünfzehn, 16 sechzehn, 17 siebzehn, 18 achtzehn, 19 neunzehn, 20 zwanzig.",
     "À partir de 13, on ajoute 'zehn' au chiffre de base. 6 = sechs, 7 = sieben (attention à l'orthographe)."),
    (11, "Les jours de la semaine",
     "Lundi = Montag\nMardi = Dienstag\nMercredi = Mittwoch\nJeudi = Donnerstag\nVendredi = Freitag\nSamedi = Samstag\nDimanche = Sonntag",
     "Tous les jours se terminent par '-tag' sauf Mittwoch. Toujours avec une majuscule en allemand."),
    (12, "Les mois de l'année",
     "Janvier = Januar\nFévrier = Februar\nMars = März\nAvril = April\nMai = Mai\nJuin = Juni\nJuillet = Juli\nAoût = August\nSeptembre = September\nOctobre = Oktober\nNovembre = November\nDécembre = Dezember",
     "Presque identiques au français sauf Januar, Februar, März, Juni, Juli. Majuscule obligatoire."),
    (13, "Les couleurs",
     "Rouge = rot\nBleu = blau\nVert = grün\nJaune = gelb\nNoir = schwarz\nBlanc = weiß\nGris = grau\nMarron = braun\nRose = rosa",
     "Les couleurs sont des adjectifs. Elles se placent avant le nom et prennent une terminaison."),
    (14, "Les salutations",
     "Bonjour = Guten Tag\nBonjour (matin) = Guten Morgen\nBonsoir = Guten Abend\nBonne nuit = Gute Nacht\nSalut = Hallo\nAu revoir = Auf Wiedersehen\nÀ bientôt = Bis bald\nÀ demain = Bis morgen",
     "'Guten' change en 'Gute' devant Nacht (féminin). Utilise 'Hallo' entre amis, 'Guten Tag' en formel."),
    (15, "Les formules de politesse",
     "Merci = Danke\nMerci beaucoup = Vielen Dank\nS'il te plaît / Je t'en prie = Bitte\nExcusez-moi = Entschuldigung\nPardon = Verzeihung\nJe suis désolé = Es tut mir leid\nPas de problème = Kein Problem",
     "'Bitte' a plusieurs sens : s'il te plaît, je t'en prie, de rien. Indispensable."),
    (16, "Les mots de temps",
     "Aujourd'hui = heute\nDemain = morgen\nHier = gestern\nMaintenant = jetzt\nPlus tard = später\nToujours = immer\nJamais = nie\nSouvent = oft\nParfois = manchmal",
     "Ces adverbes se placent en général après le verbe. 'nie' est l'opposé de 'immer'."),
    (17, "Les adverbes de lieu",
     "Ici = hier\nLà-bas = dort\nÀ gauche = links\nÀ droite = rechts\nTout droit = geradeaus\nEn haut = oben\nEn bas = unten\nDevant = vorne\nDerrière = hinten",
     "Très utiles pour demander le chemin : 'links', 'rechts', 'geradeaus'."),
    (18, "Les verbes de base (infinitif)",
     "Être = sein\nAvoir = haben\nFaire = machen\nAller = gehen\nVenir = kommen\nManger = essen\nBoire = trinken\nDormir = schlafen\nLire = lesen\nÉcrire = schreiben\nParler = sprechen\nÉcouter = hören\nVoir = sehen\nAcheter = kaufen\nTravailler = arbeiten\nHabiter = wohnen\nJouer = spielen\nConduire = fahren\nAttendre = warten\nAider = helfen",
     "À l'infinitif, les verbes se terminent en '-en' ou '-n'. Base de tout le vocabulaire."),
    (19, "Les adjectifs courants",
     "Grand = groß\nPetit = klein\nLong = lang\nCourt = kurz\nVieux = alt\nNouveau = neu\nJeune = jung\nBon = gut\nMauvais = schlecht\nBeau = schön\nChaud = heiß\nFroid = kalt\nRapide = schnell\nLent = langsam\nCher = teuer\nBon marché = billig",
     "Pour les adjectifs, apprends aussi la forme de base sans terminaison."),
    (20, "Les prépositions de lieu",
     "Dans = in\nSur = auf\nSous = unter\nÀ côté de = neben\nDevant = vor\nDerrière = hinter\nEntre = zwischen\nÀ = zu\nAvec = mit\nSans = ohne",
     "Attention : 'in' + datif pour la position, 'in' + accusatif pour la direction."),
    (21, "La structure d'une phrase simple",
     "Sujet + Verbe + Complément.\nExemple : Ich lerne heute Deutsch.\n(Je + apprends + aujourd'hui + l'allemand)",
     "Le verbe est toujours en deuxième position dans une phrase simple. Règle absolue."),
    (22, "Les possessifs (mon, ton, son...)",
     "Mon (masculin) = mein (ex: mein Vater)\nMa (féminin) = meine (ex: meine Mutter)\nMes (pluriel) = meine (ex: meine Eltern)\nTon (masculin) = dein (ex: dein Bruder)\nTa (féminin) = deine (ex: deine Schwester)",
     "'mein' / 'dein' au masculin-neutre. 'meine' / 'deine' au féminin et au pluriel."),
    (23, "Les nombres de 20 à 100",
     "Vingt = zwanzig\nTrente = dreißig\nQuarante = vierzig\nCinquante = fünfzig\nSoixante = sechzig\nSoixante-dix = siebzig\nQuatre-vingts = achtzig\nQuatre-vingt-dix = neunzig\nCent = hundert",
     "Après 20, on ajoute '-zig' sauf trente = dreißig (avec ß)."),
    (24, "Les phrases utiles pour l'examen",
     "Je m'appelle... = Ich heiße...\nJ'habite à... = Ich wohne in...\nJe viens de... = Ich komme aus...\nJ'ai... ans = Ich bin... Jahre alt\nJe parle... = Ich spreche...\nJe ne comprends pas = Ich verstehe nicht\nPouvez-vous répéter ? = Können Sie das wiederholen?\nComment dit-on... en allemand ? = Wie sagt man... auf Deutsch?",
     "Ces 8 phrases suffisent pour réussir la partie Sprechen de l'examen A1."),
]

def seed_essentials_cards(cursor):
    for num, title, content, explanation in ESSENTIALS_DATA:
        cursor.execute(
            """INSERT INTO essentials_cards(fiche_num, title, content, explanation) VALUES(?,?,?,?)
               ON CONFLICT(fiche_num) DO UPDATE SET title=excluded.title, content=excluded.content,
               explanation=excluded.explanation
               WHERE title!=excluded.title OR content!=excluded.content OR explanation!=excluded.explanation""",
            (num, title, content, explanation)
        )

# =========================================================
# SEED "NOM/AKK"
# =========================================================
NOMAKK_DATA = [
    (1, "La technique la plus simple : QUI ? et QUI/QUOI ?",
     "Le Nominatif désigne généralement la personne ou la chose qui fait l'action : le sujet.\n\n"
     "Exemples :\nDer Mann schläft. = L'homme dort.\nDie Frau lernt. = La femme étudie.\nDas Kind spielt. = L'enfant joue.\n\n"
     "Pose-toi la question : QUI dort ? QUI étudie ? QUI joue ?\n\n"
     "À retenir : le sujet est au Nominatif.\n\n"
     "L'Akkusativ désigne généralement la personne ou la chose sur laquelle porte directement l'action.\n\n"
     "Exemples :\nIch sehe den Mann. = Je vois l'homme.\nIch sehe die Frau. = Je vois la femme.\nIch sehe das Kind. = Je vois l'enfant.\n\n"
     "Pose-toi deux questions :\n1. Qui fait l'action ? → Ich = je.\n2. Je vois qui ? → den Mann = l'homme.\n\n"
     "Le sujet reste au Nominatif, tandis que le complément direct est à l'Akkusativ.",
     "Règle d'or : QUI fait l'action → Nominatif. QUI/QUOI reçoit l'action → Akkusativ."),
    (2, "Le tableau magique pour retenir les articles",
     "Masculin : der → den\nFéminin : die → die\nNeutre : das → das\nPluriel : die → die\n\n"
     "Au masculin, der devient den à l'Akkusativ.\n"
     "Mémorise : DER → DEN ; DIE → DIE ; DAS → DAS ; DIE → DIE.",
     "Un seul changement : der → den au masculin Akkusativ."),
    (3, "Quand utiliser EIN, EINE et EINEN ?",
     "Masculin : ein → einen\nFéminin : eine → eine\nNeutre : ein → ein\nPluriel : pas d'article indéfini\n\n"
     "Ein Mann kommt. = Un homme arrive.\nIch sehe einen Hund. = Je vois un chien.",
     "ein → einen UNIQUEMENT au masculin Akkusativ. eine et ein ne changent jamais."),
    (4, "Et avec KEIN, KEINE, KEINEN ?",
     "Masculin : kein → keinen\nFéminin : keine → keine\nNeutre : kein → kein\nPluriel : keine → keine\n\n"
     "Ich habe einen Hund. ↔ Ich habe keinen Hund.\nIch sehe eine Frau. ↔ Ich sehe keine Frau.",
     "kein → keinen au masculin Akkusativ, exactement comme ein → einen."),
    (5, "Comment savoir si un nom est DER, DIE ou DAS ?",
     "DER : der Mann, der Vater, der Bruder, der Hund\nDIE : die Frau, die Mutter, die Schwester, die Schule\nDAS : das Kind, das Haus, das Auto, das Buch\n\n"
     "Astuces : -ung, -heit, -keit → féminin. -chen, -lein → neutre. -ismus → masculin.",
     "Apprends toujours le nom avec son article."),
    (6, "La méthode en trois étapes",
     "Étape 1 : trouve le sujet (Qui fait l'action ?)\nÉtape 2 : cherche le complément direct (L'action porte sur qui/quoi ?)\nÉtape 3 : identifie le genre du nom\n\n"
     "Exemple : Ich kaufe einen Apfel.\n1. Qui achète ? → Ich.\n2. J'achète quoi ? → Apfel.\n3. Apfel est masculin : der Apfel.\n4. Masculin Akkusativ : einen Apfel.",
     "Méthode : sujet (Nom), complément direct (Akk), genre du nom."),
    (7, "Attention : tous les compléments ne sont pas à l'Akkusativ",
     "Certains verbes prennent le datif :\nIch helfe dem Mann. = J'aide l'homme.\n\n"
     "Verbes A1 à l'Akkusativ : sehen, haben, kaufen, brauchen, essen, trinken.",
     "Au niveau A1, concentre-toi sur les verbes qui prennent l'Akkusativ."),
    (8, "Ton résumé à mémoriser",
     "Masculin : der/den | ein/einen | kein/keinen\nFéminin : die/die | eine/eine | keine/keine\nNeutre : das/das | ein/ein | kein/kein\nPluriel : die/die | — | keine/keine",
     "Retiens juste : au masculin Akkusativ, der→den, ein→einen, kein→keinen."),
    (9, "Petit exercice pour vérifier que tu as compris",
     "1. ___ Mann trinkt Wasser. → Der\n2. Ich sehe ___ Hund. → einen\n3. Sie kauft ___ Tasche. → eine\n4. Er hat ___ Auto. → kein\n5. Ich habe ___ Bruder. → keinen\n6. ___ Frau lernt Deutsch. → Eine\n7. Ich sehe ___ Mann. → den\n8. Er hat ___ Schwester. → keine",
     "Fais l'exercice sans regarder les réponses. Vérifie chaque justification avec la règle QUI/QUOI."),
]

# --- Cours du Datif et du Génitif (sections 10 à 26) ---
# Sections 10 a 26 du cours NOM/AKK : Dativ et Genitiv (A1 -> A2)
# Format : (num, titre, contenu, explication)

NOMAKK_EXTRA = [

# ---------------------------------------------------------------- 10
(10, "Qu'est-ce que le Datif ? La question WEM ? (À QUI ?)",
'''Le Datif répond à la question WEM ? (À QUI ?). Il désigne la personne qui reçoit, à qui on donne, dit, montre ou écrit quelque chose : c'est le complément d'attribution (ou complément indirect).
Astuce : si en français tu peux dire « à quelqu'un », pense au Datif.

Les trois cas à comparer :
Nominativ : Wer ? Was ? → qui fait l'action (le sujet)
Akkusativ : Wen ? Was ? → qui ou quoi reçoit l'action (complément direct)
Dativ : Wem ? → à qui ? (complément d'attribution)

Exemple complet : Der Vater gibt dem Kind einen Apfel.
Wer gibt ? → der Vater (Nominativ)
Was gibt er ? → einen Apfel (Akkusativ)
Wem gibt er ? → dem Kind (Dativ)

Exemples :
Der Vater gibt dem Kind einen Apfel. = Le père donne une pomme à l'enfant.
Ich gebe dem Mann das Buch. = Je donne le livre à l'homme.
Ich helfe der Frau beim Einkaufen. = J'aide la femme à faire les courses.
Er antwortet dem Lehrer. = Il répond au professeur.
Sie schenkt dem Kind ein Spielzeug. = Elle offre un jouet à l'enfant.
Wir danken den Eltern. = Nous remercions les parents.
Das Buch gehört meinem Bruder. = Le livre appartient à mon frère.
Ich schreibe meiner Mutter eine Nachricht. = J'écris un message à ma mère.
Der Kellner bringt dem Gast das Essen. = Le serveur apporte le repas au client.
Ich zeige dem Touristen den Weg. = Je montre le chemin au touriste.
Die Lehrerin erklärt den Schülern die Regel. = La professeure explique la règle aux élèves.
Wem gehört das Auto? = À qui appartient la voiture ?
Wem schreibst du? = À qui écris-tu ?
Wem gibst du das Geld? = À qui donnes-tu l'argent ?

Attention : certains verbes allemands (helfen, danken...) prennent le Datif alors qu'en français on dit « aider quelqu'un ». Nous les verrons plus loin.''',
"Le Datif répond à WEM ? (à qui ?) : la personne qui reçoit, à qui on donne, on dit, on montre."),

# ---------------------------------------------------------------- 11
(11, "Les articles définis au Datif : dem, der, dem, den",
'''Au Datif, les articles définis changent presque tous. Apprends bien ce tableau.

Masculin : der → dem
Féminin : die → der
Neutre : das → dem
Pluriel : die → den (et le nom prend un -n)

Tableau complet des trois cas :
Cas | Masculin | Féminin | Neutre | Pluriel
Nominativ | der | die | das | die
Akkusativ | den | die | das | die
Dativ | dem | der | dem | den

Astuce : dem pour le masculin ET le neutre ; der pour le féminin ; den pour le pluriel.
Attention : der est aussi l'article du masculin au Nominatif, mais au féminin Datif il veut dire « à la ».

Masculin (dem) :
Ich helfe dem Vater im Garten. = J'aide le père dans le jardin.
Wir danken dem Lehrer. = Nous remercions le professeur.
Der Hund gehört dem Bruder. = Le chien appartient au frère.

Féminin (der) :
Ich antworte der Lehrerin. = Je réponds à la professeure.
Das Kind hilft der Mutter. = L'enfant aide la mère.
Er schenkt der Frau Blumen. = Il offre des fleurs à la femme.
Der Arzt hilft der Patientin. = Le médecin aide la patiente.

Neutre (dem) :
Wir geben dem Kind ein Eis. = Nous donnons une glace à l'enfant.
Sie glaubt dem Mädchen. = Elle croit la petite fille.
Er zeigt dem Baby das Foto. = Il montre la photo au bébé.

Pluriel (den + -n) :
Ich gebe den Kindern Brot. = Je donne du pain aux enfants.
Der Lehrer hilft den Schülern. = Le professeur aide les élèves.
Sie dankt den Freunden. = Elle remercie les amis.
Sie hören den Lehrern zu. = Ils écoutent les professeurs.''',
"Datif : der → dem, die → der, das → dem, die → den (+ n au nom pluriel)."),

# ---------------------------------------------------------------- 12
(12, "Les articles indéfinis, négatifs et possessifs au Datif",
'''Les mots ein, kein, mein, dein, sein, ihr, unser, euer prennent au Datif les mêmes terminaisons : -em, -er, -em, -en.

Masculin : ein → einem | kein → keinem | mein → meinem
Féminin : eine → einer | keine → keiner | meine → meiner
Neutre : ein → einem | kein → keinem | mein → meinem
Pluriel : pas d'article | keine → keinen | meine → meinen

Astuce : compare avec dem, der, dem, den : einem, einer, einem, einen. La terminaison est la même que celle de l'article défini.

Avec ein / kein :
Ich gebe einem Mann Geld. = Je donne de l'argent à un homme.
Sie hilft einem Kind. = Elle aide un enfant.
Ich schreibe einer Freundin einen Brief. = J'écris une lettre à une amie.
Er antwortet einer Kundin. = Il répond à une cliente.
Ich glaube keinem Verkäufer. = Je ne crois aucun vendeur.
Sie gibt keinem Kind Süßigkeiten. = Elle ne donne de bonbons à aucun enfant.
Ich glaube keiner Zeitung. = Je ne crois aucun journal.
Er gibt keinen Kindern Geld. = Il ne donne d'argent à aucun enfant.

Avec mein / dein / sein / ihr / unser :
Er schreibt seiner Schwester eine SMS. = Il écrit un SMS à sa sœur.
Wir gratulieren unserem Lehrer zum Geburtstag. = Nous souhaitons un bon anniversaire à notre professeur.
Sie zeigt ihrem Kind das Buch. = Elle montre le livre à son enfant.
Ich gebe meinen Eltern das Geld. = Je donne l'argent à mes parents.
Du hilfst deiner Oma im Haushalt. = Tu aides ta grand-mère à la maison.
Das Auto gehört seinem Vater. = La voiture appartient à son père.
Das Handy gehört meiner Tante. = Le téléphone appartient à ma tante.
Er dankt seinen Freunden für die Hilfe. = Il remercie ses amis pour l'aide.
Wir schreiben unseren Kunden eine E-Mail. = Nous écrivons un e-mail à nos clients.''',
"Datif : einem / einer / einem / (keinen au pluriel) ; mêmes terminaisons pour kein-, mein-, dein-, sein-."),

# ---------------------------------------------------------------- 13
(13, "Les pronoms personnels au Datif : mir, dir, ihm, ihr...",
'''Les pronoms personnels changent aussi au Datif. Voici le tableau avec les trois cas :

Personne | Nominativ | Akkusativ | Dativ
1re sing. | ich | mich | mir
2e sing. | du | dich | dir
3e masc. | er | ihn | ihm
3e fém. | sie | sie | ihr
3e neutre | es | es | ihm
1re plur. | wir | uns | uns
2e plur. | ihr | euch | euch
3e plur. | sie | sie | ihnen
Politesse | Sie | Sie | Ihnen

Remarque : à la politesse, Sie et Ihnen prennent toujours une majuscule. Au Datif, uns et euch sont identiques à l'Akkusativ.

Exemples :
Das Buch gehört mir. = Le livre est à moi.
Das Handy gehört dir. = Le téléphone est à toi.
Ich sehe ihn. = Je le vois.
Ich helfe ihm. = Je l'aide.
Wir sehen sie. = Nous les voyons.
Wir helfen ihnen. = Nous les aidons.
Der Lehrer antwortet ihr. = Le professeur lui répond.
Ich schenke ihr Blumen. = Je lui offre des fleurs.
Der Kuchen schmeckt uns. = Le gâteau nous plaît.
Ich bringe euch Wasser. = Je vous apporte de l'eau.
Der Lehrer erklärt ihnen die Aufgabe. = Le professeur leur explique l'exercice.
Kann ich Ihnen helfen? = Puis-je vous aider ?
Der Hut steht dir gut. = Le chapeau te va bien.
Das Geschenk ist für dich. = Le cadeau est pour toi.
Kommst du mit uns? = Tu viens avec nous ?
Er wohnt bei mir. = Il habite chez moi.''',
"Datif : mir, dir, ihm, ihr, ihm, uns, euch, ihnen, Ihnen."),

# ---------------------------------------------------------------- 14
(14, "Les verbes qui se construisent TOUJOURS avec le Datif",
'''Certains verbes allemands exigent le Datif pour la personne, même si en français on dit « aider quelqu'un » ou « remercier quelqu'un ». Il faut les apprendre par cœur, avec jemandem (à quelqu'un).

Liste des verbes :
helfen = aider
danken = remercier
gehören = appartenir
gefallen = plaire
schmecken = avoir bon goût, plaire au goût
passen = convenir, aller (taille, style)
antworten = répondre
gratulieren = féliciter
folgen = suivre
fehlen = manquer
zuhören = écouter
wehtun = faire mal
glauben = croire (quelqu'un)
begegnen = croiser, rencontrer par hasard
erlauben = permettre
verzeihen = pardonner
zustimmen = approuver, être d'accord
gehorchen = obéir
vertrauen = faire confiance
gelingen = réussir
einfallen = venir à l'esprit
schaden = nuire
nützen = être utile
imponieren = impressionner

Exemples, un par verbe :
Sie hilft ihrem Bruder bei den Hausaufgaben. = Elle aide son frère à faire ses devoirs.
Ich danke Ihnen für die Hilfe. = Je vous remercie pour votre aide.
Die Tasche gehört der Lehrerin. = Le sac appartient à la professeure.
Die Stadt gefällt mir sehr. = La ville me plaît beaucoup.
Die Suppe schmeckt mir gut. = La soupe me plaît, elle est bonne.
Die Schuhe passen mir nicht. = Les chaussures ne me vont pas.
Er antwortet dem Chef per E-Mail. = Il répond au chef par e-mail.
Wir gratulieren dir zum Geburtstag. = Nous te souhaitons un joyeux anniversaire.
Das Kind folgt der Mutter. = L'enfant suit la mère.
Du fehlst mir. = Tu me manques.
Hörst du mir zu? = Tu m'écoutes ?
Der Kopf tut mir weh. = J'ai mal à la tête.
Ich glaube dir nicht. = Je ne te crois pas.
Ich bin dem Chef im Bus begegnet. = J'ai croisé le chef dans le bus.
Der Lehrer erlaubt uns eine Pause. = Le professeur nous accorde une pause.
Bitte verzeih mir. = Pardonne-moi, s'il te plaît.
Ich stimme dir zu. = Je suis d'accord avec toi.
Der Hund gehorcht seinem Herrn. = Le chien obéit à son maître.
Ich vertraue meinem Freund. = Je fais confiance à mon ami.
Der Kuchen ist mir gelungen. = Le gâteau m'a réussi.
Mir fällt der Name nicht ein. = Le nom ne me vient pas à l'esprit.
Rauchen schadet der Gesundheit. = Fumer nuit à la santé.
Das nützt mir nichts. = Ça ne me sert à rien.
Der Sportler imponiert den Kindern. = Le sportif impressionne les enfants.''',
"Apprends ces verbes avec jemandem : helfen, danken, gehören, gefallen, schmecken, passen, antworten..."),

# ---------------------------------------------------------------- 15
(15, "Les verbes avec DEUX compléments : Datif (personne) + Akkusativ (chose)",
'''Avec beaucoup de verbes, il y a deux compléments : la PERSONNE à qui on donne est au Datif et la CHOSE donnée est à l'Akkusativ.
Schéma : Sujet (Nom) + verbe + personne (Dativ) + chose (Akkusativ).

Liste des verbes :
geben = donner
schenken = offrir
zeigen = montrer
schicken = envoyer
bringen = apporter
kaufen = acheter (pour quelqu'un)
leihen = prêter
erklären = expliquer
sagen = dire
empfehlen = recommander
erzählen = raconter
anbieten = proposer
mitbringen = apporter avec soi
wünschen = souhaiter
schreiben = écrire
verkaufen = vendre

Exemples :
Ich gebe meinem Bruder das Handy. = Je donne le téléphone à mon frère.
Sie schenkt ihrer Oma einen Kuchen. = Elle offre un gâteau à sa grand-mère.
Er zeigt seinem Freund die neue Wohnung. = Il montre le nouvel appartement à son ami.
Ich schicke dir ein Foto. = Je t'envoie une photo.
Der Kellner bringt uns die Speisekarte. = Le serveur nous apporte la carte.
Papa kauft dem Kind ein Eis. = Papa achète une glace à l'enfant.
Kannst du mir dein Fahrrad leihen? = Peux-tu me prêter ton vélo ?
Der Lehrer erklärt uns die Grammatik. = Le professeur nous explique la grammaire.
Sag mir bitte deinen Namen. = Dis-moi ton nom, s'il te plaît.
Ich empfehle dir diesen Film. = Je te recommande ce film.
Oma erzählt den Enkeln eine Geschichte. = Grand-mère raconte une histoire à ses petits-enfants.
Die Verkäuferin bietet dem Kunden einen Rabatt an. = La vendeuse propose une réduction au client.
Ich bringe dir aus Douala Mangos mit. = Je te rapporte des mangues de Douala.
Wir wünschen euch eine gute Reise. = Nous vous souhaitons un bon voyage.
Sie schreibt ihrem Chef eine E-Mail. = Elle écrit un e-mail à son chef.
Der Händler verkauft der Frau frischen Fisch. = Le commerçant vend du poisson frais à la femme.

Attention aux pièges : beantworten et fragen se construisent avec l'Akkusativ seulement.
Ich beantworte die Frage. = Je réponds à la question.
Ich antworte dem Lehrer. = Je réponds au professeur.
Ich frage den Lehrer. = Je demande au professeur.''',
"Personne → Datif, chose → Akkusativ. Piège : beantworten et fragen prennent l'Akkusativ."),

# ---------------------------------------------------------------- 16
(16, "L'ordre des mots : Datif avant Akkusativ ?",
'''Quand une phrase contient un complément au Datif et un à l'Akkusativ, l'ordre dépend de ce que l'on utilise : des noms ou des pronoms.

Règle 1 : deux noms → Datif (personne) avant Akkusativ (chose).
Règle 2 : un pronom et un nom → le pronom passe en premier, quel que soit son cas.
Règle 3 : deux pronoms → Akkusativ avant Datif.

Règle 1, deux noms :
Der Verkäufer gibt der Kundin die Tüte. = Le vendeur donne le sachet à la cliente.
Ich schenke meiner Mutter einen Schal. = J'offre une écharpe à ma mère.
Sie zeigt dem Gast das Zimmer. = Elle montre la chambre à l'invité.
Der Lehrer erklärt den Kindern die Aufgabe. = Le professeur explique l'exercice aux enfants.

Règle 2, pronom Datif avant nom Akkusativ :
Der Verkäufer gibt ihr die Tüte. = Le vendeur lui donne le sachet.
Ich schenke ihm einen Schal. = Je lui offre une écharpe.
Sie zeigt uns das Zimmer. = Elle nous montre la chambre.
Der Lehrer erklärt mir die Aufgabe. = Le professeur m'explique l'exercice.

Règle 2, pronom Akkusativ avant nom Datif :
Der Verkäufer gibt sie der Kundin. = Le vendeur la donne à la cliente.
Ich schenke ihn meiner Mutter. = Je l'offre à ma mère.
Sie zeigt es dem Gast. = Elle le montre à l'invité.
Der Lehrer erklärt sie den Kindern. = Le professeur l'explique aux enfants.

Règle 3, deux pronoms (Akkusativ puis Datif) :
Der Verkäufer gibt sie ihr. = Le vendeur la lui donne.
Ich schenke ihn ihr. = Je le lui offre.
Sie zeigt es uns. = Elle nous le montre.
Ich gebe es dir. = Je te le donne.
Er schickt es mir. = Il me l'envoie.
Kannst du mir bitte das Salz geben? = Peux-tu me passer le sel, s'il te plaît ?''',
"Deux noms : Datif puis Akkusativ. Deux pronoms : Akkusativ puis Datif. Un pronom passe avant un nom."),

# ---------------------------------------------------------------- 17
(17, "Les prépositions TOUJOURS suivies du Datif",
'''Certaines prépositions sont toujours suivies du Datif, sans exception. Voici le moyen mnémotechnique à chanter : aus - bei - mit - nach - seit - von - zu. À cette liste s'ajoutent außer, gegenüber et ab.

Mnémotechnique : aus, bei, mit, nach, seit, von, zu : toujours le Datif !

Contractions à connaître :
zu dem → zum
zu der → zur
bei dem → beim
von dem → vom

aus (de, hors de, en matière de) :
Ich komme aus Kamerun. = Je viens du Cameroun.
Er kommt aus dem Haus. = Il sort de la maison.
Der Tisch ist aus Holz. = La table est en bois.
Sie nimmt das Buch aus der Tasche. = Elle sort le livre du sac.

bei (chez, près de, pendant) :
Ich wohne bei meinen Eltern. = J'habite chez mes parents.
Sie arbeitet bei einer Bank. = Elle travaille dans une banque.
Beim Essen spricht man nicht. = On ne parle pas pendant le repas.

mit (avec, en moyen de transport) :
Ich fahre mit dem Bus. = Je vais en bus.
Er isst mit einem Löffel. = Il mange avec une cuillère.
Wir spielen mit unseren Freunden. = Nous jouons avec nos amis.
Kommst du mit mir? = Tu viens avec moi ?

nach (après, vers une ville ou un pays) :
Nach der Schule gehe ich nach Hause. = Après l'école, je rentre à la maison.
Wir fahren nach Douala. = Nous allons à Douala.
Nach dem Essen trinke ich Tee. = Après le repas, je bois du thé.

seit (depuis) :
Ich lerne seit einem Jahr Deutsch. = J'apprends l'allemand depuis un an.
Er wohnt seit drei Monaten in Yaoundé. = Il habite à Yaoundé depuis trois mois.
Es regnet seit einer Stunde. = Il pleut depuis une heure.

von (de, par) :
Das Geschenk ist von meiner Tante. = Le cadeau vient de ma tante.
Das ist ein Freund von mir. = C'est un de mes amis.
Vom Bahnhof zum Hotel sind es fünf Minuten. = De la gare à l'hôtel, il y a cinq minutes.

zu (à, chez quelqu'un, vers) :
Ich gehe zum Arzt. = Je vais chez le médecin.
Sie geht zur Schule. = Elle va à l'école.
Kommst du zu meiner Party? = Tu viens à ma fête ?
Er kommt zu Fuß. = Il vient à pied.

außer (sauf) :
Alle sind da außer meinem Bruder. = Tous sont là sauf mon frère.
Außer mir kommt niemand. = Personne ne vient sauf moi.

gegenüber (en face de) :
Das Café liegt gegenüber der Schule. = Le café est en face de l'école.
Die Post ist dem Rathaus gegenüber. = La poste est en face de la mairie.

ab (à partir de) :
Ab dem ersten Januar arbeite ich hier. = À partir du premier janvier, je travaille ici.
Ab nächster Woche habe ich Urlaub. = À partir de la semaine prochaine, j'ai des congés.''',
"aus, bei, mit, nach, seit, von, zu (+ außer, gegenüber, ab) : toujours le Datif."),

# ---------------------------------------------------------------- 18
(18, "Les prépositions de lieu à double régime : WO ? ou WOHIN ?",
'''Neuf prépositions peuvent être suivies du Datif OU de l'Akkusativ : in, an, auf, hinter, neben, über, unter, vor, zwischen.
Pour choisir, pose la question :
WO ? (où ? : lieu, pas de mouvement) → Dativ
WOHIN ? (vers où ? : mouvement, direction) → Akkusativ

Verbes de position (WO ?) : liegen, stehen, sitzen, hängen
Verbes de mouvement (WOHIN ?) : legen, stellen, setzen, hängen, gehen, fahren

Contractions : in dem → im ; an dem → am ; in das → ins ; an das → ans ; auf das → aufs.

Paires contrastées, d'abord WO ? puis WOHIN ? :
Ich bin in der Schule. = Je suis à l'école.
Ich gehe in die Schule. = Je vais à l'école.
Das Buch liegt auf dem Tisch. = Le livre est sur la table.
Ich lege das Buch auf den Tisch. = Je pose le livre sur la table.
Das Bild hängt an der Wand. = Le tableau est accroché au mur.
Ich hänge das Bild an die Wand. = J'accroche le tableau au mur.
Der Hund liegt unter dem Tisch. = Le chien est couché sous la table.
Der Hund läuft unter den Tisch. = Le chien court sous la table.
Die Katze sitzt hinter dem Sofa. = Le chat est assis derrière le canapé.
Die Katze springt hinter das Sofa. = Le chat saute derrière le canapé.
Das Auto steht vor dem Haus. = La voiture est devant la maison.
Ich stelle das Auto vor das Haus. = Je gare la voiture devant la maison.
Der Stuhl steht neben dem Bett. = La chaise est à côté du lit.
Ich stelle den Stuhl neben das Bett. = Je mets la chaise à côté du lit.
Die Lampe hängt über dem Tisch. = La lampe est suspendue au-dessus de la table.
Ich hänge die Lampe über den Tisch. = J'accroche la lampe au-dessus de la table.
Die Bank ist zwischen dem Park und der Schule. = La banque est entre le parc et l'école.
Er stellt die Vase zwischen die Bücher. = Il met le vase entre les livres.

Avec les contractions :
Wir sind im Kino. = Nous sommes au cinéma.
Wir gehen ins Kino. = Nous allons au cinéma.
Sie sind am Meer. = Ils sont au bord de la mer.
Sie fahren ans Meer. = Ils vont au bord de la mer.
Er wohnt auf dem Land. = Il habite à la campagne.
Er zieht aufs Land. = Il déménage à la campagne.''',
"WO ? (lieu) → Datif. WOHIN ? (mouvement) → Akkusativ."),

# ---------------------------------------------------------------- 19
(19, "Le Datif au pluriel : den + un -n au nom",
'''Au Datif pluriel, l'article est toujours den, et le nom prend un -n à la fin (den Kindern, den Freunden).

Tableau :
die Kinder → den Kindern
die Freunde → den Freunden
die Männer → den Männern
die Bücher → den Büchern
die Häuser → den Häusern

Exceptions : pas de -n supplémentaire si le pluriel finit déjà par -n ou par -s.
die Frauen → den Frauen
die Schwestern → den Schwestern
die Eltern → den Eltern
die Autos → den Autos
die Hotels → den Hotels

Avec -n ajouté :
Sie erzählt den Kindern eine Geschichte. = Elle raconte une histoire aux enfants.
Er zeigt den Freunden seine Fotos. = Il montre ses photos aux amis.
Der Chef dankt den Männern für die Arbeit. = Le chef remercie les hommes pour le travail.
Der Direktor gratuliert den Schülern zum Erfolg. = Le directeur félicite les élèves pour leur réussite.
Ich kaufe Obst bei den Händlern. = J'achète des fruits chez les marchands.
Der Bürgermeister dankt den Müttern. = Le maire remercie les mères.
Wir spielen mit den Hunden. = Nous jouons avec les chiens.
Wir sitzen an den Tischen. = Nous sommes assis aux tables.
Sie lesen in den Büchern. = Ils lisent dans les livres.
Die Familien wohnen in den Häusern. = Les familles habitent dans les maisons.

Sans -n supplémentaire :
Die Ärztin hilft den Frauen. = La médecin aide les femmes.
Ich schreibe meinen Schwestern eine Karte. = J'écris une carte à mes sœurs.
Das Kind hilft den Eltern im Haushalt. = L'enfant aide ses parents à la maison.
Die Touristen wohnen in den Hotels. = Les touristes logent dans les hôtels.
Die Katze sitzt auf den Autos. = Le chat est assis sur les voitures.''',
"Datif pluriel : den + nom avec un -n (sauf pluriel déjà en -n ou en -s)."),

# ---------------------------------------------------------------- 20
(20, "Le Datif dans les expressions de tous les jours",
'''Beaucoup d'expressions très courantes utilisent le Datif, surtout avec mir, dir et Ihnen. Apprends-les comme des phrases toutes faites.

Santé et sentiments :
Wie geht es dir? = Comment vas-tu ?
Wie geht es Ihnen? = Comment allez-vous ?
Mir geht es gut. = Je vais bien.
Mir ist kalt. = J'ai froid.
Mir ist warm. = J'ai chaud.
Ist dir kalt? = As-tu froid ?
Mir ist langweilig. = Je m'ennuie.
Mir ist schlecht. = J'ai la nausée.
Mir tut der Bauch weh. = J'ai mal au ventre.
Mir tut der Rücken weh. = J'ai mal au dos.

Politesse et goûts :
Es tut mir leid. = Je suis désolé.
Das gefällt mir. = Ça me plaît.
Das schmeckt mir. = C'est bon, ça me plaît.
Das passt mir gut. = Ça me convient bien.
Das ist mir egal. = Ça m'est égal.
Das ist mir wichtig. = C'est important pour moi.
Das tut mir gut. = Ça me fait du bien.
Das kommt mir bekannt vor. = Ça me dit quelque chose.
Mir fehlen die Worte. = Les mots me manquent.

Souhaits et échanges :
Gute Besserung! = Bon rétablissement !
Viel Spaß! = Amuse-toi bien !
Ich wünsche dir viel Glück. = Je te souhaite bonne chance.
Danke, dir auch! = Merci, à toi aussi !
Kannst du mir helfen? = Peux-tu m'aider ?
Gehört das dir? = C'est à toi ?''',
"Mir ist kalt, es tut mir leid, das gefällt mir : ces expressions utilisent le Datif."),

# ---------------------------------------------------------------- 21
(21, "Le Génitif : la question WESSEN ? (possession)",
'''Le Génitif exprime la possession ou l'appartenance. Il répond à la question WESSEN ? (DE QUI ? À QUI EST... ?). En français il correspond à « de », « du », « de la », « des ».

Articles au Génitif :
Masculin : der → des (+ -s ou -es au nom)
Féminin : die → der
Neutre : das → des (+ -s ou -es au nom)
Pluriel : die → der
Avec ein / mein : eines, einer, eines ; meines, meiner, meines.

Règle pour le nom : au masculin et au neutre singulier, on ajoute -s (des Vaters, des Lehrers) ou -es pour les mots courts d'une syllabe (des Kindes, des Hauses, des Mannes). Le féminin et le pluriel ne changent pas.

Le Génitif se place APRÈS le nom qu'il complète : das Auto des Vaters (la voiture du père).

Exemples :
Das Auto des Vaters ist neu. = La voiture du père est neuve.
Die Tasche der Mutter ist rot. = Le sac de la mère est rouge.
Das Spielzeug des Kindes liegt im Garten. = Le jouet de l'enfant est dans le jardin.
Die Bücher der Schüler liegen auf dem Tisch. = Les livres des élèves sont sur la table.
Der Name des Lehrers ist Herr Müller. = Le nom du professeur est Monsieur Müller.
Das Dach des Hauses ist grün. = Le toit de la maison est vert.
Die Farbe der Wand ist weiß. = La couleur du mur est blanche.
Die Eltern der Kinder wohnen in Douala. = Les parents des enfants habitent à Douala.
Das Ende des Films ist traurig. = La fin du film est triste.
Der Preis des Kuchens ist hoch. = Le prix du gâteau est élevé.
Die Tür der Schule ist offen. = La porte de l'école est ouverte.
Der Direktor der Schule ist sehr nett. = Le directeur de l'école est très gentil.
Das Zimmer meines Bruders ist groß. = La chambre de mon frère est grande.
Die Freundin meiner Schwester kommt heute. = L'amie de ma sœur vient aujourd'hui.
Wessen Buch ist das? = À qui est ce livre ?
Wessen Tasche liegt auf dem Stuhl? = À qui est le sac posé sur la chaise ?''',
"Génitif : des (masc. et neutre, + s), der (fém. et pluriel). Question : WESSEN ?"),

# ---------------------------------------------------------------- 22
(22, "Le Génitif avec les noms propres, et la forme courante « von + Datif »",
'''Avec un prénom, on ajoute simplement -s, sans apostrophe, et on le place AVANT le nom : Annas Buch (le livre d'Anna).
Si le prénom finit par -s, -x, -z ou -ß, on met une apostrophe : Thomas' Auto, Max' Fahrrad.

Dans la langue de tous les jours, on utilise très souvent « von + Datif » à la place du Génitif : das Auto von meinem Vater.

Comparaison :
das Auto des Vaters ↔ das Auto von meinem Vater
Annas Buch ↔ das Buch von Anna
Thomas' Auto ↔ das Auto von Thomas

Attention : à l'oral on entend parfois « dem Paul sein Auto » : c'est familier, à ne pas écrire.

Avec les prénoms :
Annas Buch ist neu. = Le livre d'Anna est neuf.
Pauls Auto ist schnell. = La voiture de Paul est rapide.
Samuels Haus ist groß. = La maison de Samuel est grande.
Marias Mutter ist Lehrerin. = La mère de Maria est professeure.
Graces Schwester wohnt in Yaoundé. = La sœur de Grace habite à Yaoundé.
Blaises Handy ist kaputt. = Le téléphone de Blaise est cassé.

Prénoms finissant en -s, -x, -z :
Thomas' Auto ist alt. = La voiture de Thomas est vieille.
Max' Fahrrad steht vor der Schule. = Le vélo de Max est devant l'école.
Alex' Hund bellt laut. = Le chien d'Alex aboie fort.

Avec von + Datif :
Das Auto von meinem Vater ist neu. = La voiture de mon père est neuve.
Das Buch von Anna ist interessant. = Le livre d'Anna est intéressant.
Die Tasche von meiner Mutter ist rot. = Le sac de ma mère est rouge.
Das ist das Haus von meinen Großeltern. = C'est la maison de mes grands-parents.
Der Freund von meiner Schwester heißt Paul. = L'ami de ma sœur s'appelle Paul.
Das ist das Handy von Samuel. = C'est le téléphone de Samuel.
Das Handy von meinem Bruder ist neu. = Le téléphone de mon frère est neuf.''',
"Annas Buch, Thomas' Auto : le prénom + s se place avant le nom. À l'oral : von + Datif."),

# ---------------------------------------------------------------- 23
(23, "Les prépositions avec le Génitif",
'''Certaines prépositions sont suivies du Génitif. Au niveau A2, retiens les six plus utiles : wegen (à cause de), trotz (malgré), während (pendant), statt ou anstatt (au lieu de), innerhalb (à l'intérieur de, dans un délai de), außerhalb (en dehors de).
Il existe d'autres prépositions du Génitif (aufgrund, diesseits...) mais on les apprendra plus tard.

Remarque : à l'oral, on entend très souvent le Datif après wegen, trotz et während (par exemple wegen dem Regen). À l'écrit et dans les examens, utilise le Génitif.

wegen (à cause de) :
Wegen des Regens bleiben wir zu Hause. = À cause de la pluie, nous restons à la maison.
Wegen der Hitze trinke ich viel Wasser. = À cause de la chaleur, je bois beaucoup d'eau.
Wegen meiner Arbeit habe ich wenig Zeit. = À cause de mon travail, j'ai peu de temps.

trotz (malgré) :
Trotz des Regens gehen wir spazieren. = Malgré la pluie, nous allons nous promener.
Trotz der Schmerzen arbeitet sie weiter. = Malgré les douleurs, elle continue à travailler.
Trotz des Verkehrs kommt er pünktlich. = Malgré la circulation, il arrive à l'heure.

während (pendant) :
Während des Unterrichts spricht man nicht. = Pendant le cours, on ne parle pas.
Während der Ferien besuche ich meine Oma. = Pendant les vacances, je rends visite à ma grand-mère.

statt / anstatt (au lieu de) :
Statt des Busses nehme ich das Fahrrad. = Au lieu du bus, je prends le vélo.
Anstatt eines Kuchens kaufen wir Eis. = Au lieu d'un gâteau, nous achetons une glace.
Statt der Suppe nehme ich einen Salat. = Au lieu de la soupe, je prends une salade.

innerhalb (à l'intérieur de, dans un délai de) :
Innerhalb der Stadt gibt es viele Taxis. = À l'intérieur de la ville, il y a beaucoup de taxis.
Innerhalb einer Woche bekommst du das Paket. = Tu reçois le colis dans un délai d'une semaine.

außerhalb (en dehors de) :
Außerhalb der Stadt ist es ruhig. = En dehors de la ville, c'est calme.
Er wohnt außerhalb des Dorfes. = Il habite en dehors du village.''',
"wegen, trotz, während, statt, innerhalb, außerhalb : toujours le Génitif à l'écrit."),

# ---------------------------------------------------------------- 24
(24, "Tableau récapitulatif des 4 cas",
'''Voici le grand tableau des quatre cas. Apprends-le par ordre : Nominativ, Akkusativ, Dativ, Genitiv.

Les questions :
Nominativ : Wer ? Was ? → qui fait l'action
Akkusativ : Wen ? Was ? → qui ou quoi reçoit l'action
Dativ : Wem ? → à qui ?
Genitiv : Wessen ? → de qui, à qui appartient ?

Articles définis :
Cas | Masculin | Féminin | Neutre | Pluriel
Nominativ | der | die | das | die
Akkusativ | den | die | das | die
Dativ | dem | der | dem | den
Genitiv | des | der | des | der

Articles indéfinis (ein) :
Cas | Masculin | Féminin | Neutre | Pluriel
Nominativ | ein | eine | ein | —
Akkusativ | einen | eine | ein | —
Dativ | einem | einer | einem | —
Genitiv | eines | einer | eines | —

Négation (kein) :
Cas | Masculin | Féminin | Neutre | Pluriel
Nominativ | kein | keine | kein | keine
Akkusativ | keinen | keine | kein | keine
Dativ | keinem | keiner | keinem | keinen
Genitiv | keines | keiner | keines | keiner

Astuces mémo :
Féminin : die, die, der, der.
Pluriel : die, die, den, der.
Seul le masculin change à l'Akkusativ : der → den.
Le masculin et le neutre sont identiques au Dativ (dem) et au Génitif (des).
Le Dativ pluriel prend toujours un -n au nom.
Les quatre W : Wer, Wen, Wem, Wessen.

Les quatre cas avec les mêmes personnes :
Der Lehrer ist nett. = Le professeur est gentil.
Ich kenne den Lehrer. = Je connais le professeur.
Ich danke dem Lehrer. = Je remercie le professeur.
Das ist das Buch des Lehrers. = C'est le livre du professeur.
Die Frau ist Ärztin. = La femme est médecin.
Ich kenne die Frau. = Je connais la femme.
Ich telefoniere mit der Frau. = Je téléphone à la femme.
Das ist die Tasche der Frau. = C'est le sac de la femme.
Das Kind lacht laut. = L'enfant rit fort.
Ich rufe das Kind. = J'appelle l'enfant.
Ich gebe dem Kind ein Brot. = Je donne un pain à l'enfant.
Das ist das Fahrrad des Kindes. = C'est le vélo de l'enfant.
Die Kinder spielen im Garten. = Les enfants jouent dans le jardin.
Ich sehe die Kinder im Garten. = Je vois les enfants dans le jardin.
Ich helfe den Kindern im Garten. = J'aide les enfants dans le jardin.
Das sind die Spielsachen der Kinder. = Ce sont les jouets des enfants.''',
"Quatre cas, quatre questions : Wer ? Wen ? Wem ? Wessen ? Seul le masculin change à l'Akkusativ."),

# ---------------------------------------------------------------- 25
(25, "La méthode en 4 questions pour trouver le bon cas",
'''Pour trouver le cas de chaque groupe de mots, pose ces quatre questions dans l'ordre :
1. Qui fait l'action ? Wer ? → Nominativ
2. Sur qui ou sur quoi porte l'action ? Wen ? Was ? → Akkusativ
3. À qui ? Wem ? → Dativ
4. De qui, à qui appartient ? Wessen ? → Genitiv
Pense aussi aux prépositions : mit, bei, zu... → Dativ ; wegen, trotz... → Genitiv ; in, an, auf... → WO ? Dativ, WOHIN ? Akkusativ.

Phrase 1 :
Der Lehrer gibt dem Schüler das Buch. = Le professeur donne le livre à l'élève.
Qui donne ? → der Lehrer : Nominativ
À qui ? → dem Schüler : Dativ
Il donne quoi ? → das Buch : Akkusativ

Phrase 2 :
Die Mutter kauft ihrem Sohn ein Fahrrad. = La mère achète un vélo à son fils.
Qui achète ? → die Mutter : Nominativ
À qui ? → ihrem Sohn : Dativ (masculin : ihrem)
Elle achète quoi ? → ein Fahrrad : Akkusativ (neutre : ein)

Phrase 3 :
Das Auto des Direktors steht vor dem Haus. = La voiture du directeur est devant la maison.
Qu'est-ce qui est devant la maison ? → das Auto : Nominativ
De qui est la voiture ? → des Direktors : Genitiv (masculin : des + -s)
Où ? → vor dem Haus : Dativ (WO ? donc Dativ)

Phrase 4 :
Wegen des Regens bleibt die Familie zu Hause. = À cause de la pluie, la famille reste à la maison.
Qui reste ? → die Familie : Nominativ
À cause de quoi ? → wegen des Regens : Genitiv (wegen + Genitiv)

Phrase 5 :
Mein Bruder schenkt seiner Freundin eine Blume. = Mon frère offre une fleur à sa petite amie.
Qui offre ? → mein Bruder : Nominativ
À qui ? → seiner Freundin : Dativ (féminin : seiner)
Il offre quoi ? → eine Blume : Akkusativ (féminin : eine)

Phrase 6 :
Wir fahren mit dem Bus in die Stadt. = Nous allons en ville en bus.
Qui voyage ? → wir : Nominativ
Avec quoi ? → mit dem Bus : Dativ (mit + Datif)
Vers où ? → in die Stadt : Akkusativ (WOHIN ? donc Akkusativ)''',
"Méthode : Wer ? Wen/Was ? Wem ? Wessen ? Et vérifie les prépositions."),

# ---------------------------------------------------------------- 26
(26, "Exercices de vérification : Datif, Génitif, Akkusativ",
'''Fais chaque série sans regarder les réponses, puis vérifie avec la règle (Wem ? Wen ? Wessen ?).

Série A : le Datif
1. Ich helfe ___ Mann. → dem
2. Wir danken ___ Lehrerin. → der
3. Das Buch gehört ___ Kind. → dem
4. Er antwortet ___ Eltern. → den
5. Sie gibt ___ Frau einen Brief. → der
6. Ich gratuliere ___ Freunden. → den
7. Der Schüler hört ___ Lehrer zu. → dem
8. Er schenkt ___ Mutter Blumen. → der

Série B : le Génitif
1. Das Auto ___ Vaters ist neu. → des
2. Die Tasche ___ Mutter ist rot. → der
3. Das Spielzeug ___ Kind___ liegt dort. → des Kindes
4. Wegen ___ Regen___ bleiben wir hier. → des Regens
5. Trotz ___ Kälte gehen wir hinaus. → der
6. Während ___ Ferien reisen wir. → der
7. Die Bücher ___ Schüler sind neu. → der
8. Das Zimmer ___ Bruder___ ist klein. → des Bruders

Série C : Akkusativ ou Datif ?
1. Ich sehe ___ Hund. → den
2. Wir besuchen ___ Großeltern. → die
3. Ich brauche ___ Stift. → einen
4. Er gibt ___ Kind einen Ball. → dem
5. Sie schreibt ___ Freundin einen Brief. → der
6. Ich habe ___ Zeit. → keine
7. Er fährt mit ___ Bus zur Schule. → dem
8. Ich kaufe ___ Brot und ___ Wasser. → das, das

Série D : quel cas ? (Nominativ, Akkusativ, Dativ ou Genitiv)
1. Ich schenke dem Kind einen Ball. → dem Kind : Dativ ; einen Ball : Akkusativ
2. Der Hund des Nachbarn bellt. → der Hund : Nominativ ; des Nachbarn : Genitiv
3. Ich sehe den Lehrer. → den Lehrer : Akkusativ
4. Er hilft seiner Schwester. → seiner Schwester : Dativ (helfen + Dativ)
5. Wir wohnen in der Stadt. → in der Stadt : Dativ (WO ?)
6. Wir fahren in die Stadt. → in die Stadt : Akkusativ (WOHIN ?)
7. Wegen des Regens bleiben wir hier. → des Regens : Genitiv (wegen)
8. Das Buch gehört meinem Bruder. → meinem Bruder : Dativ (gehören + Dativ)
9. Sie kauft einen Apfel für die Kinder. → einen Apfel : Akkusativ ; die Kinder : Akkusativ (für + Akkusativ)
10. Die Tasche der Lehrerin ist neu. → die Tasche : Nominativ ; der Lehrerin : Genitiv''',
"Pose toujours la question : Wer ? Wen ? Wem ? Wessen ? Et vérifie le verbe et la préposition."),

]

# Cours NOM / AKK / DATIV / GENITIV : les lignes d'exemples sont écrites « ALLEMAND = FRANÇAIS ».
NOMAKK_ALL = NOMAKK_DATA + NOMAKK_EXTRA

# (clé, titre de la partie, première section, dernière section)
NOMAKK_GROUPS = [
    ("nomakk", "Nominatif et Akkusativ", 1, 9),
    ("dativ", "Le Datif", 10, 20),
    ("genitiv", "Le Génitif", 21, 23),
    ("recap", "Récapitulatif et exercices", 24, 26),
]
NOMAKK_ALL_KEY = "all"
NOMAKK_ALL_TITLE = "Tout le cours : Nominatif, Akkusativ, Datif, Génitif"

def _nomakk_pairs(content):
    """Lignes « Allemand = Français » d'une section → liste de (allemand, français)."""
    out = []
    for line in (content or "").split("\n"):
        s = line.strip()
        if "=" in s and "|" not in s and "→" not in s:
            de, fr = s.split("=", 1)
            de, fr = de.strip(), fr.strip()
            if de and fr and len(de) < 200 and len(fr) < 200:
                out.append((de, fr))
    return out

def seed_nomakk_sections(cursor):
    for num, title, content, explanation in NOMAKK_ALL:
        cursor.execute(
            """INSERT INTO nomakk_sections(sec_num, title, content, explanation) VALUES(?,?,?,?)
               ON CONFLICT(sec_num) DO UPDATE SET title=excluded.title, content=excluded.content,
               explanation=excluded.explanation
               WHERE title!=excluded.title OR content!=excluded.content OR explanation!=excluded.explanation""",
            (num, title, content, explanation)
        )

def seed_nomakk_playlist(cursor):
    def items_for(lo, hi):
        items = []
        for num, title, content, explanation in NOMAKK_ALL:
            if lo <= num <= hi:
                # le titre de la section est en FRANÇAIS (voix française), puis « Abschnitt n » (voix allemande)
                items.append({"fr": f"Section {num} : {title}", "de": f"Abschnitt {num}"})
                # attention : à gauche du « = » c'est l'ALLEMAND, à droite le FRANÇAIS
                for de, fr in _nomakk_pairs(content):
                    items.append({"fr": fr, "de": de})
        return items
    lists = [(NOMAKK_ALL_KEY, NOMAKK_ALL_TITLE, items_for(1, 999))]
    for key, title, lo, hi in NOMAKK_GROUPS:
        lists.append((key, title, items_for(lo, hi)))
    for key, title, items in lists:
        payload = json.dumps(items, ensure_ascii=False)
        cursor.execute(
            """INSERT INTO nomakk_playlist(key, title, items_json) VALUES(?,?,?)
               ON CONFLICT(key) DO UPDATE SET title=excluded.title, items_json=excluded.items_json
               WHERE title!=excluded.title OR items_json!=excluded.items_json""",
            (key, title, payload)
        )

def seed_speak_playlists(cursor):
    for theme_order, (theme, items) in enumerate(SPEAK_PHRASES_DATA, start=1):
        payload = json.dumps([{"fr": fr, "de": de} for fr, de in items], ensure_ascii=False)
        cursor.execute(
            """INSERT INTO speak_playlists(kind, key, title, items_json) VALUES(?,?,?,?)
            ON CONFLICT(kind, key) DO UPDATE SET title=excluded.title, items_json=excluded.items_json
            WHERE title!=excluded.title OR items_json!=excluded.items_json""",
            ("speak", theme, theme, payload)
        )
    essentials_items = []
    for num, title, content, explanation in ESSENTIALS_DATA:
        for line in content.split("\n"):
            if "=" in line:
                left, right = line.split("=", 1)
                essentials_items.append({
                    "fr": left.strip(),
                    "de": right.strip()
                })
    payload = json.dumps(essentials_items, ensure_ascii=False)
    cursor.execute(
        """INSERT INTO speak_playlists(kind, key, title, items_json) VALUES(?,?,?,?)
            ON CONFLICT(kind, key) DO UPDATE SET title=excluded.title, items_json=excluded.items_json
            WHERE title!=excluded.title OR items_json!=excluded.items_json""",
        ("essentials", "all", "Les essentiels A1", payload)
    )

# =========================================================
# === NEFERTI : SEED DES SCÉNARIOS (49 étapes) ===
# 10 catégories, multi-embranchements, mémoire par user.
# =========================================================
NEFERTI_SCENARIOS = [
    # --- Catégorie 1 : SE PRÉSENTER ---
    ("Se présenter", "intro_1",
     "Hallo! Ich bin Neferti. Wie heißt du?",
     "Bonjour ! Je suis Neferti. Comment t'appelles-tu ?",
     "Ich heiße", "heiße,heisse,name,bin",
     "present_name", "present_name", "name", 1),
    ("Se présenter", "present_name",
     "Freut mich, dich kennenzulernen! Wie alt bist du?",
     "Enchantée de te connaître ! Quel âge as-tu ?",
     "Ich bin ... Jahre alt", "jahre,alt,bin",
     "present_city", "present_city", "age", 2),
    ("Se présenter", "present_city",
     "Super! Und woher kommst du?",
     "Super ! Et d'où viens-tu ?",
     "Ich komme aus ...", "komme,aus,land",
     "present_city2", "present_city2", "country", 3),
    ("Se présenter", "present_city2",
     "Interessant! Und wo wohnst du jetzt?",
     "Intéressant ! Et où habites-tu maintenant ?",
     "Ich wohne in ...", "wohne,in,stadt",
     "present_job", "present_job", "city", 4),
    ("Se présenter", "present_job",
     "Ah, schön! Was machst du beruflich? Bist du Student oder arbeitest du?",
     "Ah, bien ! Que fais-tu comme métier ? Es-tu étudiant ou travailles-tu ?",
     "Ich bin Student / Ich arbeite als ...", "student,arbeite,beruf",
     "present_hobby", "present_hobby", "job", 5),
    ("Se présenter", "present_hobby",
     "Toll! Was machst du gern in deiner Freizeit?",
     "Génial ! Que fais-tu volontiers pendant ton temps libre ?",
     "Ich ... gern", "gern,freizeit,hobby",
     "present_language", "present_language", "hobby", 6),
    ("Se présenter", "present_language",
     "Sehr gut! Welche Sprachen sprichst du?",
     "Très bien ! Quelles langues parles-tu ?",
     "Ich spreche ...", "spreche,sprachen,deutsch,französisch",
     "present_finish", "present_finish", "languages", 7),
    ("Se présenter", "present_finish",
     "Wunderbar! Du hast dich super vorgestellt. Möchtest du weiter üben?",
     "Merveilleux ! Tu t'es super bien présenté(e). Veux-tu continuer à t'entraîner ?",
     "Ja / Nein", "ja,nein,gerne,weiter",
     "family_1", "free_1", "", 8),

    # --- Catégorie 2 : FAMILLE ---
    ("Famille", "family_1",
     "Erzähl mir von deiner Familie. Hast du Geschwister?",
     "Parle-moi de ta famille. As-tu des frères et sœurs ?",
     "Ich habe ... Bruder / Schwester", "bruder,schwester,geschwister,habe",
     "family_2", "family_2", "siblings", 9),
    ("Famille", "family_2",
     "Ah, schön! Hast du Kinder?",
     "Ah, bien ! As-tu des enfants ?",
     "Ja, ich habe ... Kinder / Nein, ich habe keine Kinder", "kinder,habe,ja,nein",
     "family_3", "family_3", "children", 10),
    ("Famille", "family_3",
     "Und deine Eltern? Wo wohnen sie?",
     "Et tes parents ? Où habitent-ils ?",
     "Sie wohnen in ...", "eltern,wohnen,mutter,vater",
     "family_4", "family_4", "parents_city", 11),
    ("Famille", "family_4",
     "Sehr schön! Hast du ein Haustier?",
     "Très bien ! As-tu un animal de compagnie ?",
     "Ja, ich habe einen Hund / eine Katze", "haustier,hund,katze,habe",
     "animal_1", "animal_no", "pet", 12),

    # --- Catégorie 3 : ANIMAUX ---
    ("Animaux", "animal_1",
     "Erzähl mir von deinem Haustier! Wie heißt es?",
     "Parle-moi de ton animal ! Comment s'appelle-t-il ?",
     "Er / Sie heißt ...", "heißt,name,hund,katze",
     "animal_2", "animal_2", "pet_name", 13),
    ("Animaux", "animal_2",
     "Wie alt ist dein Haustier?",
     "Quel âge a ton animal ?",
     "Er / Sie ist ... Jahre alt", "jahre,alt,ist",
     "animal_3", "animal_3", "pet_age", 14),
    ("Animaux", "animal_3",
     "Was frisst dein Haustier gern?",
     "Que mange volontiers ton animal ?",
     "Er / Sie frisst ...", "frisst,isst,futter",
     "animal_4", "animal_4", "pet_food", 15),
    ("Animaux", "animal_4",
     "Süß! Magst du auch andere Tiere?",
     "Mignon ! Aimes-tu aussi d'autres animaux ?",
     "Ja, ich mag ... / Nein, ich mag ...", "mag,tiere,ja,nein",
     "animal_5", "animal_5", "fav_animal", 16),
    ("Animaux", "animal_5",
     "Toll! Welches Tier magst du nicht?",
     "Génial ! Quel animal n'aimes-tu pas ?",
     "Ich mag ... nicht", "mag,nicht,tier",
     "food_1", "food_1", "", 17),
    ("Animaux", "animal_no",
     "Kein Problem! Welches Tier magst du am liebsten?",
     "Pas de problème ! Quel animal préfères-tu ?",
     "Ich mag ... am liebsten", "mag,tier,liebsten",
     "animal_5", "animal_5", "fav_animal", 18),

    # --- Catégorie 4 : NOURRITURE ---
    ("Nourriture", "food_1",
     "Jetzt über Essen! Was isst du gern?",
     "Maintenant parlons nourriture ! Qu'aimes-tu manger ?",
     "Ich esse gern ...", "esse,gern,isst",
     "food_2", "food_2", "fav_food", 19),
    ("Nourriture", "food_2",
     "Lecker! Was trinkst du gern?",
     "Délicieux ! Que bois-tu volontiers ?",
     "Ich trinke gern ...", "trinke,gern,getränk",
     "food_3", "food_3", "fav_drink", 20),
    ("Nourriture", "food_3",
     "Kannst du kochen?",
     "Sais-tu cuisiner ?",
     "Ja, ich kann kochen / Nein, ich kann nicht kochen", "kochen,kann,ja,nein",
     "food_4", "food_4", "can_cook", 21),
    ("Nourriture", "food_4",
     "Was ist dein Lieblingsessen?",
     "Quel est ton plat préféré ?",
     "Mein Lieblingsessen ist ...", "lieblingsessen,essen",
     "food_5", "food_5", "fav_dish", 22),
    ("Nourriture", "food_5",
     "Interessant! Isst du auch deutsche Spezialitäten?",
     "Intéressant ! Manges-tu aussi des spécialités allemandes ?",
     "Ja / Nein, ich esse ...", "deutsch,spezialität,ja,nein",
     "hobby_1", "hobby_1", "", 23),

    # --- Catégorie 5 : LOISIRS ---
    ("Loisirs", "hobby_1",
     "Was machst du gern in deiner Freizeit?",
     "Que fais-tu volontiers pendant ton temps libre ?",
     "Ich ... gern", "gern,freizeit,hobby",
     "hobby_2", "hobby_2", "hobby", 24),
    ("Loisirs", "hobby_2",
     "Treibst du Sport?",
     "Fais-tu du sport ?",
     "Ja, ich spiele ... / Nein, ich mache keinen Sport", "sport,spiele,ja,nein",
     "hobby_3", "hobby_3", "sport", 25),
    ("Loisirs", "hobby_3",
     "Hörst du gern Musik?",
     "Aimes-tu écouter de la musique ?",
     "Ja, ich höre gern ...", "musik,höre,ja,nein",
     "hobby_4", "hobby_4", "music", 26),
    ("Loisirs", "hobby_4",
     "Siehst du gern Filme?",
     "Aimes-tu regarder des films ?",
     "Ja, ich sehe gern ... / Nein", "filme,sehe,ja,nein",
     "hobby_5", "hobby_5", "movies", 27),
    ("Loisirs", "hobby_5",
     "Liest du gern Bücher?",
     "Aimes-tu lire des livres ?",
     "Ja, ich lese gern ...", "bücher,lese,ja,nein",
     "travel_1", "travel_1", "books", 28),

    # --- Catégorie 6 : VOYAGE ---
    ("Voyage", "travel_1",
     "Reist du gern? Wohin bist du letztes Jahr gefahren?",
     "Aimes-tu voyager ? Où es-tu allé(e) l'année dernière ?",
     "Ich bin nach ... gefahren", "reise,gefahren,nach",
     "travel_2", "travel_2", "last_trip", 29),
    ("Voyage", "travel_2",
     "Schön! Wie bist du dorthin gereist? Mit dem Auto oder mit dem Zug?",
     "Bien ! Comment as-tu voyagé là-bas ? En voiture ou en train ?",
     "Ich bin mit ... gereist", "auto,zug,flugzeug,gereist",
     "travel_3", "travel_3", "transport", 30),
    ("Voyage", "travel_3",
     "Wie lange warst du dort?",
     "Combien de temps y es-tu resté(e) ?",
     "Ich war ... Tage / Wochen dort", "tage,wochen,dort,war",
     "travel_4", "travel_4", "trip_duration", 31),
    ("Voyage", "travel_4",
     "War es schön? Was hast du dort gemacht?",
     "C'était beau ? Qu'as-tu fait là-bas ?",
     "Ich habe ... gemacht", "gemacht,schön,war",
     "travel_5", "travel_5", "trip_activity", 32),
    ("Voyage", "travel_5",
     "Möchtest du nächstes Jahr wieder reisen?",
     "Veux-tu voyager à nouveau l'année prochaine ?",
     "Ja, ich möchte nach ... reisen", "reisen,möchte,nächstes",
     "work_1", "work_1", "", 33),

    # --- Catégorie 7 : TRAVAIL / ÉTUDES ---
    ("Travail", "work_1",
     "Was machst du beruflich? Arbeitest du oder studierst du?",
     "Que fais-tu comme métier ? Travailles-tu ou étudies-tu ?",
     "Ich arbeite als ... / Ich studiere ...", "arbeite,studiere,beruf",
     "work_2", "work_2", "job", 34),
    ("Travail", "work_2",
     "Wie lange arbeitest du schon?",
     "Depuis combien de temps travailles-tu ?",
     "Ich arbeite seit ... Jahren", "jahre,seit,arbeite",
     "work_3", "work_3", "work_duration", 35),
    ("Travail", "work_3",
     "Gefällt dir deine Arbeit?",
     "Ton travail te plaît-il ?",
     "Ja, sehr / Nein, nicht so", "gefällt,arbeit,ja,nein",
     "work_4", "work_4", "likes_job", 36),
    ("Travail", "work_4",
     "Wann beginnt deine Arbeit oder dein Unterricht?",
     "Quand commence ton travail ou tes cours ?",
     "Um ... Uhr", "uhr,beginnt",
     "work_5", "work_5", "work_start", 37),
    ("Travail", "work_5",
     "Warum lernst du Deutsch?",
     "Pourquoi apprends-tu l'allemand ?",
     "Ich lerne Deutsch, weil ...", "deutsch,weil,lerne",
     "weather_1", "weather_1", "why_german", 38),

    # --- Catégorie 8 : MÉTÉO ---
    ("Météo", "weather_1",
     "Wie ist das Wetter heute bei dir?",
     "Quel temps fait-il aujourd'hui chez toi ?",
     "Es ist ... / Es regnet / Es schneit", "wetter,regnet,schneit,ist",
     "weather_2", "weather_2", "weather_today", 39),
    ("Météo", "weather_2",
     "Welche Jahreszeit magst du am liebsten?",
     "Quelle saison préfères-tu ?",
     "Ich mag ... am liebsten", "jahreszeit,sommer,winter,mag",
     "weather_3", "weather_3", "fav_season", 40),
    ("Météo", "weather_3",
     "Warum magst du diese Jahreszeit?",
     "Pourquoi aimes-tu cette saison ?",
     "Weil ...", "weil,jahreszeit",
     "objects_1", "objects_1", "", 41),

    # --- Catégorie 9 : OBJETS ---
    ("Objets", "objects_1",
     "Ich zeige dir ein Bild. Was ist das? (Ein Handy) Antworte: Das ist ein ...",
     "Je te montre une image. Qu'est-ce que c'est ? (Un téléphone) Réponds : C'est un ...",
     "Das ist ein Handy", "handy,telefon,das",
     "objects_2", "objects_2", "", 42),
    ("Objets", "objects_2",
     "Richtig! Wofür benutzt du dein Handy?",
     "Correct ! À quoi utilises-tu ton téléphone ?",
     "Ich benutze mein Handy für ...", "benutze,handy,für",
     "objects_3", "objects_3", "phone_use", 43),
    ("Objets", "objects_3",
     "Was ist das? (Ein Buch) Antworte: Das ist ein ...",
     "Qu'est-ce que c'est ? (Un livre) Réponds : C'est un ...",
     "Das ist ein Buch", "buch,das,ein",
     "objects_4", "objects_4", "", 44),
    ("Objets", "objects_4",
     "Richtig! Liest du gern Bücher?",
     "Correct ! Aimes-tu lire des livres ?",
     "Ja, ich lese gern / Nein", "lese,bücher,ja,nein",
     "free_1", "free_1", "", 45),

    # --- Catégorie 10 : MODE LIBRE (fallbacks) ---
    ("Libre", "free_1",
     "Möchtest du über etwas Bestimmtes sprechen? Wähle ein Thema: Familie, Essen, Hobbys oder Reisen?",
     "Veux-tu parler de quelque chose en particulier ? Choisis un thème : famille, nourriture, loisirs ou voyage ?",
     "Familie / Essen / Hobbys / Reisen", "familie,essen,hobbys,reisen",
     "family_1", "food_1", "", 46),
    ("Libre", "free_2",
     "Erzähl mir mehr! Was hast du gestern gemacht?",
     "Raconte-moi plus ! Qu'as-tu fait hier ?",
     "Ich habe ... gemacht", "gestern,gemacht,habe",
     "free_3", "free_3", "yesterday", 47),
    ("Libre", "free_3",
     "Interessant! Und was machst du morgen?",
     "Intéressant ! Et que fais-tu demain ?",
     "Morgen ...", "morgen,mache",
     "free_4", "free_4", "tomorrow", 48),
    ("Libre", "free_4",
     "Sehr schön! Jetzt bist du dran: Stelle mir eine Frage!",
     "Très bien ! Maintenant à toi : pose-moi une question !",
     "Wie heißt du? / Wo wohnst du?", "frage,wie,wo",
     "present_finish", "present_finish", "", 49),
]

def seed_neferti_scenarios(cursor):
    for (category, step_key, de, fr, expected, keywords,
         f_yes, f_no, mem_key, order_i) in NEFERTI_SCENARIOS:
        cursor.execute(
            """INSERT INTO neferti_scenarios
            (category, step_key, neferti_de, neferti_fr, expected_de, keywords,
             followup_yes, followup_no, memory_key, order_index)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(step_key) DO UPDATE SET category=excluded.category, neferti_de=excluded.neferti_de,
              neferti_fr=excluded.neferti_fr, expected_de=excluded.expected_de, keywords=excluded.keywords,
              followup_yes=excluded.followup_yes, followup_no=excluded.followup_no,
              memory_key=excluded.memory_key, order_index=excluded.order_index""",
            (category, step_key, de, fr, expected, keywords,
             f_yes, f_no, mem_key, order_i)
        )

# =========================================================
# === NEFERTI v4.2 : BANQUE DE QUESTIONS (1000+ questions de la vie courante) ===
# Chaque entrée : (thème, question DE, question FR, réponse modèle DE, réponse modèle FR, mots-clés)
# Les questions vont du plus facile au plus riche à l'intérieur de chaque thème.
# =========================================================
NEFERTI_BANK = [
    ('Famille et amis', 'Hast du Geschwister?', 'As-tu des frères et sœurs ?', 'Ja, ich habe zwei Brüder und eine Schwester.', "Oui, j'ai deux frères et une sœur.", 'brüder,schwester,zwei'),
    ('Famille et amis', 'Wie heißt deine Mutter?', "Comment s'appelle ta mère ?", 'Meine Mutter heißt Berthe.', "Ma mère s'appelle Berthe.", 'mutter,heißt,berthe'),
    ('Famille et amis', 'Wie alt ist dein Vater?', 'Quel âge a ton père ?', 'Mein Vater ist fünfzig Jahre alt.', 'Mon père a cinquante ans.', 'vater,alt,jahre'),
    ('Famille et amis', 'Wo wohnt deine Familie?', 'Où habite ta famille ?', 'Meine Familie wohnt in Yaoundé, nicht weit vom Markt.', 'Ma famille habite à Yaoundé, pas loin du marché.', 'familie,wohnt,yaoundé'),
    ('Famille et amis', 'Wie viele Personen sind in deiner Familie?', 'Combien de personnes y a-t-il dans ta famille ?', 'In meiner Familie sind wir sieben Personen.', 'Dans ma famille, nous sommes sept personnes.', 'personen,familie,sieben'),
    ('Famille et amis', 'Hast du einen besten Freund oder eine beste Freundin?', 'As-tu un meilleur ami ou une meilleure amie ?', 'Ja, ich habe einen besten Freund. Er heißt Paul.', "Oui, j'ai un meilleur ami. Il s'appelle Paul.", 'freund,freundin,heißt'),
    ('Famille et amis', 'Wie heißt dein Onkel?', "Comment s'appelle ton oncle ?", 'Mein Onkel heißt Joseph und wohnt in Douala.', "Mon oncle s'appelle Joseph et habite à Douala.", 'onkel,heißt,wohnt'),
    ('Famille et amis', 'Hast du Kinder?', 'As-tu des enfants ?', 'Nein, ich habe noch keine Kinder.', "Non, je n'ai pas encore d'enfants.", 'kinder,keine,noch'),
    ('Famille et amis', 'Wer kocht bei dir zu Hause?', 'Qui cuisine chez toi ?', 'Bei uns zu Hause kocht meistens meine Mutter.', "Chez nous, c'est le plus souvent ma mère qui cuisine.", 'kocht,mutter,meistens'),
    ('Famille et amis', 'Wie ist deine Mutter?', 'Comment est ta mère ?', 'Meine Mutter ist freundlich und sehr fleißig.', 'Ma mère est gentille et très travailleuse.', 'mutter,freundlich,fleißig'),
    ('Famille et amis', 'Wie sieht dein Bruder aus?', 'À quoi ressemble ton frère ?', 'Mein Bruder ist groß und hat kurze schwarze Haare.', 'Mon frère est grand et a les cheveux courts et noirs.', 'bruder,groß,haare'),
    ('Famille et amis', 'Wann hast du Geburtstag?', 'Quand est ton anniversaire ?', 'Ich habe im März Geburtstag.', 'Mon anniversaire est en mars.', 'geburtstag,märz,habe'),
    ('Famille et amis', 'Was schenkst du deiner Mutter zum Geburtstag?', "Qu'offres-tu à ta mère pour son anniversaire ?", 'Ich schenke meiner Mutter Blumen und einen Kuchen.', "J'offre à ma mère des fleurs et un gâteau.", 'schenke,blumen,kuchen'),
    ('Famille et amis', 'Magst du deine Nachbarn?', 'Aimes-tu tes voisins ?', 'Ja, ich mag meine Nachbarn. Sie sind sehr nett.', "Oui, j'aime bien mes voisins. Ils sont très gentils.", 'nachbarn,mag,nett'),
    ('Famille et amis', 'Wo wohnt deine Oma?', 'Où habite ta grand-mère ?', 'Meine Oma wohnt in einem Dorf im Westen.', "Ma grand-mère habite dans un village à l'Ouest.", 'oma,wohnt,dorf'),
    ('Famille et amis', 'Wie oft telefonierst du mit deiner Familie?', 'À quelle fréquence appelles-tu ta famille ?', 'Ich telefoniere jeden Abend mit meiner Familie.', "J'appelle ma famille tous les soirs.", 'telefoniere,familie,abend'),
    ('Famille et amis', 'Was machst du gern mit deinen Freunden?', 'Que fais-tu volontiers avec tes amis ?', 'Mit meinen Freunden spiele ich gern Fußball.', "Avec mes amis, j'aime jouer au football.", 'freunden,gern,fußball,spiele'),
    ('Famille et amis', 'Wann siehst du deine Freunde?', 'Quand vois-tu tes amis ?', 'Ich sehe meine Freunde meistens am Wochenende.', 'Je vois mes amis le plus souvent le week-end.', 'freunde,wochenende,sehe'),
    ('Famille et amis', 'Wer ist der Älteste in deiner Familie?', 'Qui est le plus âgé de ta famille ?', 'Mein Großvater ist der Älteste. Er ist achtzig Jahre alt.', 'Mon grand-père est le plus âgé. Il a quatre-vingts ans.', 'großvater,älteste,alt'),
    ('Famille et amis', 'Bist du verheiratet?', 'Es-tu marié(e) ?', 'Nein, ich bin noch nicht verheiratet.', 'Non, je ne suis pas encore marié(e).', 'verheiratet,noch,nicht'),
    ('Famille et amis', 'Wie viele Cousins und Cousinen hast du?', 'Combien de cousins et cousines as-tu ?', 'Ich habe ungefähr zwanzig Cousins und Cousinen.', "J'ai environ vingt cousins et cousines.", 'cousins,cousinen,zwanzig'),
    ('Famille et amis', 'Was ist dein Vater von Beruf?', 'Quel est le métier de ton père ?', 'Mein Vater ist Lehrer an einer Schule.', 'Mon père est enseignant dans une école.', 'vater,lehrer,schule'),
    ('Famille et amis', 'Wo arbeitet deine Mutter?', 'Où travaille ta mère ?', 'Meine Mutter arbeitet auf dem Markt. Sie verkauft Gemüse.', 'Ma mère travaille au marché. Elle vend des légumes.', 'arbeitet,mutter,markt,verkauft'),
    ('Famille et amis', 'Wer wohnt neben dir?', 'Qui habite à côté de chez toi ?', 'Neben mir wohnt eine nette Familie mit drei Kindern.', 'À côté de chez moi habite une famille sympathique avec trois enfants.', 'neben,wohnt,familie,kindern'),
    ('Famille et amis', 'Ist deine Familie groß oder klein?', 'Ta famille est-elle grande ou petite ?', 'Meine Familie ist klein. Wir sind nur vier Personen.', 'Ma famille est petite. Nous ne sommes que quatre personnes.', 'familie,klein,personen'),
    ('Famille et amis', 'Was isst deine Familie gern am Sonntag?', 'Que mange ta famille volontiers le dimanche ?', 'Am Sonntag isst meine Familie gern Reis mit Hähnchen.', 'Le dimanche, ma famille aime manger du riz avec du poulet.', 'sonntag,isst,reis,hähnchen'),
    ('Famille et amis', 'Hast du eine WhatsApp-Gruppe mit deiner Familie?', 'As-tu un groupe WhatsApp avec ta famille ?', 'Ja, wir haben eine WhatsApp-Gruppe. Dort schreiben wir jeden Tag.', 'Oui, nous avons un groupe WhatsApp. Nous y écrivons tous les jours.', 'whatsapp,gruppe,schreiben'),
    ('Famille et amis', 'Wie alt sind deine Geschwister?', 'Quel âge ont tes frères et sœurs ?', 'Mein Bruder ist zwanzig und meine Schwester ist fünfzehn.', 'Mon frère a vingt ans et ma sœur a quinze ans.', 'bruder,schwester,zwanzig,fünfzehn'),
    ('Famille et amis', 'Siehst du deine Großeltern oft?', 'Vois-tu souvent tes grands-parents ?', 'Ja, ich sehe meine Großeltern jeden Sonntag.', 'Oui, je vois mes grands-parents tous les dimanches.', 'großeltern,sehe,sonntag'),
    ('Famille et amis', 'Wer in deiner Familie lacht am meisten?', 'Qui rit le plus dans ta famille ?', 'Meine kleine Schwester lacht am meisten. Sie ist sehr lustig.', "C'est ma petite sœur qui rit le plus. Elle est très drôle.", 'schwester,lacht,lustig'),
    ('Famille et amis', 'Wie viele Freunde hast du?', "Combien d'amis as-tu ?", 'Ich habe ungefähr zehn gute Freunde.', "J'ai environ dix bons amis.", 'freunde,gute,zehn'),
    ('Famille et amis', 'Wo triffst du dich mit deinen Freunden?', 'Où retrouves-tu tes amis ?', 'Wir treffen uns oft in einem kleinen Café in Yaoundé.', 'Nous nous retrouvons souvent dans un petit café à Yaoundé.', 'treffe,treffen,café'),
    ('Famille et amis', 'Ist dein Vater streng?', 'Ton père est-il sévère ?', 'Nein, mein Vater ist nicht streng. Er ist ruhig und lustig.', "Non, mon père n'est pas sévère. Il est calme et drôle.", 'vater,streng,ruhig,lustig'),
    ('Famille et amis', 'Hast du Neffen oder Nichten?', 'As-tu des neveux ou des nièces ?', 'Ja, ich habe einen Neffen und zwei Nichten.', "Oui, j'ai un neveu et deux nièces.", 'neffen,neffe,nichten'),
    ('Famille et amis', 'Wer bringt die Kinder zur Schule?', "Qui emmène les enfants à l'école ?", 'Bei uns bringt mein Vater die Kinder zur Schule.', "Chez nous, c'est mon père qui emmène les enfants à l'école.", 'bringt,kinder,schule,vater'),
    ('Famille et amis', 'Wie sind deine Nachbarn?', 'Comment sont tes voisins ?', 'Meine Nachbarn sind sehr freundlich.', 'Mes voisins sont très aimables.', 'nachbarn,freundlich,sehr'),
    ('Famille et amis', 'Wie nennst du deine Großmutter?', 'Comment appelles-tu ta grand-mère ?', 'Ich nenne meine Großmutter Oma. Auf Französisch sage ich Mamie.', "J'appelle ma grand-mère Oma. En français, je dis Mamie.", 'nenne,großmutter,oma,mamie'),
    ('Famille et amis', 'Hast du Verwandte im Ausland?', "As-tu de la famille à l'étranger ?", 'Ja, mein Onkel lebt in Frankreich und meine Cousine in Kanada.', 'Oui, mon oncle vit en France et ma cousine au Canada.', 'onkel,lebt,frankreich,cousine'),
    ('Famille et amis', 'Wer hilft dir zu Hause?', "Qui t'aide à la maison ?", 'Meine kleine Schwester hilft mir im Haushalt.', "Ma petite sœur m'aide aux tâches ménagères.", 'hilft,schwester,haushalt'),
    ('Famille et amis', 'Wie lange kennst du deine Nachbarn schon?', 'Depuis combien de temps connais-tu tes voisins ?', 'Ich kenne meine Nachbarn schon seit fünf Jahren.', 'Je connais mes voisins depuis cinq ans.', 'kenne,nachbarn,jahren'),
    ('Famille et amis', 'Was hast du gestern mit deinen Freunden gemacht?', "Qu'as-tu fait hier avec tes amis ?", 'Gestern haben wir bei einem Freund gekocht und viel gelacht.', 'Hier, nous avons cuisiné chez un ami et beaucoup ri.', 'gestern,gekocht,gelacht'),
    ('Famille et amis', 'Wer hat dich zuletzt besucht?', "Qui t'a rendu visite en dernier ?", 'Vor zwei Tagen hat mich mein Cousin besucht.', "Il y a deux jours, mon cousin m'a rendu visite.", 'besucht,cousin,tagen'),
    ('Famille et amis', 'Hast du heute schon mit deiner Mutter telefoniert?', "As-tu déjà téléphoné à ta mère aujourd'hui ?", 'Ja, ich habe heute Morgen mit meiner Mutter telefoniert.', "Oui, j'ai téléphoné à ma mère ce matin.", 'telefoniert,mutter,heute'),
    ('Famille et amis', 'Welches Geschenk hast du zuletzt bekommen?', 'Quel cadeau as-tu reçu récemment ?', 'Ich habe von meiner Schwester ein schönes Kleid bekommen.', "J'ai reçu une belle robe de ma sœur.", 'bekommen,kleid,schwester'),
    ('Famille et amis', 'Wo hast du deinen besten Freund kennengelernt?', 'Où as-tu rencontré ton meilleur ami ?', 'Ich habe ihn in der Schule kennengelernt.', "Je l'ai rencontré à l'école.", 'kennengelernt,schule,ihn'),
    ('Famille et amis', 'Bist du als Kind oft zu deinen Großeltern gefahren?', 'Allais-tu souvent chez tes grands-parents quand tu étais enfant ?', 'Ja, in den Ferien bin ich immer zu meinen Großeltern gefahren.', "Oui, pendant les vacances, j'allais toujours chez mes grands-parents.", 'großeltern,gefahren,ferien'),
    ('Famille et amis', 'Wie war dein letzter Besuch bei deiner Familie?', 'Comment était ta dernière visite chez ta famille ?', 'Er war sehr schön. Wir haben viel gegessen und Fotos gemacht.', 'Il était très beau. Nous avons beaucoup mangé et pris des photos.', 'besuch,schön,gegessen,fotos'),
    ('Famille et amis', 'Mit wem hast du gestern gesprochen?', 'Avec qui as-tu parlé hier ?', 'Gestern habe ich lange mit meinem Bruder gesprochen.', "Hier, j'ai longuement parlé avec mon frère.", 'gestern,gesprochen,bruder,lange'),
    ('Famille et amis', 'Was hast du beim letzten Familienfest gegessen?', "Qu'as-tu mangé à la dernière fête de famille ?", 'Wir haben Ndolé mit Kochbananen und Fisch gegessen.', 'Nous avons mangé du ndolé avec des plantains et du poisson.', 'gegessen,ndolé,fisch,kochbananen'),
    ('Famille et amis', 'Hast du als Kind mit deinen Geschwistern gestritten?', 'Te disputais-tu avec tes frères et sœurs quand tu étais enfant ?', 'Ja, wir haben oft gestritten, aber danach haben wir wieder zusammen gespielt.', 'Oui, nous nous sommes souvent disputés, mais après nous avons rejoué ensemble.', 'gestritten,gespielt,oft'),
    ('Famille et amis', 'Wen hast du zuletzt angerufen?', 'Qui as-tu appelé en dernier ?', 'Zuletzt habe ich meine Tante in Douala angerufen.', "En dernier, j'ai appelé ma tante à Douala.", 'angerufen,tante,zuletzt'),
    ('Famille et amis', 'Wohin bist du mit deiner Familie zuletzt gefahren?', 'Où es-tu allé avec ta famille la dernière fois ?', 'Wir sind letztes Jahr nach Kribi ans Meer gefahren.', "L'année dernière, nous sommes allés à Kribi au bord de la mer.", 'gefahren,kribi,meer'),
    ('Famille et amis', 'Wer hat dir als Kind Geschichten erzählt?', 'Qui te racontait des histoires quand tu étais enfant ?', 'Als Kind hat mir meine Oma oft Geschichten erzählt.', "Enfant, c'est ma grand-mère qui me racontait souvent des histoires.", 'geschichten,erzählt,oma,kind'),
    ('Famille et amis', 'Wen hast du letzte Woche zum Essen eingeladen?', 'Qui as-tu invité à manger la semaine dernière ?', 'Letzte Woche habe ich meine Cousine zum Essen eingeladen.', "La semaine dernière, j'ai invité ma cousine à manger.", 'eingeladen,essen,cousine'),
    ('Famille et amis', 'Wen besuchst du nächste Woche?', 'Qui vas-tu voir la semaine prochaine ?', 'Nächste Woche besuche ich meine Schwester in Bamenda.', 'La semaine prochaine, je rends visite à ma sœur à Bamenda.', 'besuche,schwester,nächste'),
    ('Famille et amis', 'Möchtest du später Kinder haben?', 'Aimerais-tu avoir des enfants plus tard ?', 'Ja, ich möchte später drei Kinder haben.', 'Oui, je voudrais avoir trois enfants plus tard.', 'möchte,kinder,später,drei'),
    ('Famille et amis', 'Was möchtest du deinen Eltern einmal kaufen?', 'Que voudrais-tu acheter un jour à tes parents ?', 'Ich möchte meinen Eltern ein Auto kaufen.', 'Je voudrais acheter une voiture à mes parents.', 'möchte,eltern,auto,kaufen'),
    ('Famille et amis', 'Was planst du für die Ferien mit deinen Freunden?', 'Que prévois-tu pour les vacances avec tes amis ?', 'Wir wollen in den Ferien zusammen den Mont Cameroun besteigen.', 'Pendant les vacances, nous voulons gravir ensemble le mont Cameroun.', 'ferien,wollen,besteigen'),
    ('Famille et amis', 'Wen lädst du zu deiner Hochzeit ein?', 'Qui invites-tu à ton mariage ?', 'Ich lade meine ganze Familie und alle Freunde ein.', "J'invite toute ma famille et tous mes amis.", 'familie,freunde,lade,ganze'),
    ('Famille et amis', 'Was machst du heute Abend mit deiner Familie?', 'Que fais-tu ce soir avec ta famille ?', 'Heute Abend essen wir zusammen und spielen Karten.', 'Ce soir, nous mangeons ensemble et jouons aux cartes.', 'abend,essen,karten,zusammen'),
    ('Famille et amis', 'Wann willst du heiraten?', 'Quand veux-tu te marier ?', 'Ich will heiraten, wenn ich eine gute Arbeit habe.', "Je veux me marier quand j'aurai un bon travail.", 'heiraten,will,arbeit'),
    ('Famille et amis', 'Wo möchtest du in zehn Jahren mit deiner Familie wohnen?', 'Où aimerais-tu habiter avec ta famille dans dix ans ?', 'In zehn Jahren möchte ich mit meiner Familie in einem kleinen Haus wohnen.', 'Dans dix ans, je voudrais habiter avec ma famille dans une petite maison.', 'möchte,wohnen,haus,familie'),
    ('Famille et amis', 'Was findest du an deiner Familie am schönsten?', "Qu'est-ce que tu trouves de plus beau dans ta famille ?", 'Ich finde es am schönsten, dass wir immer zusammen essen.', "Ce que je trouve le plus beau, c'est que nous mangeons toujours ensemble.", 'finde,schönsten,zusammen,essen'),
    ('Famille et amis', 'Wie findest du große Familien?', 'Que penses-tu des grandes familles ?', 'Ich finde große Familien toll, denn man ist nie allein.', "Je trouve les grandes familles super, car on n'est jamais seul.", 'große,familien,toll,allein'),
    ('Famille et amis', 'Was ist wichtiger für dich, Familie oder Freunde?', "Qu'est-ce qui est plus important pour toi, la famille ou les amis ?", 'Meine Familie ist mir wichtiger, weil sie immer für mich da ist.', 'Ma famille est plus importante pour moi, car elle est toujours là pour moi.', 'wichtiger,familie,weil'),
    ('Famille et amis', 'Was ist für dich ein guter Freund?', "Pour toi, qu'est-ce qu'un bon ami ?", 'Ein guter Freund ist ehrlich und hilft mir immer.', "Un bon ami est honnête et m'aide toujours.", 'freund,ehrlich,hilft'),
    ('Famille et amis', 'Findest du es gut, wenn Großeltern bei ihren Kindern wohnen?', 'Trouves-tu bien que les grands-parents vivent chez leurs enfants ?', 'Ja, das finde ich gut, weil die Großeltern viel Erfahrung haben.', "Oui, je trouve ça bien, car les grands-parents ont beaucoup d'expérience.", 'großeltern,gut,erfahrung'),
    ('Famille et amis', 'Wie wichtig ist die Familie in Kamerun?', "Quelle est l'importance de la famille au Cameroun ?", 'In Kamerun ist die Familie sehr wichtig. Wir helfen uns immer.', 'Au Cameroun, la famille est très importante. Nous nous aidons toujours.', 'kamerun,familie,wichtig,helfen'),
    ('Famille et amis', 'Was nervt dich an deinen Nachbarn?', "Qu'est-ce qui t'agace chez tes voisins ?", 'Mich nervt, dass meine Nachbarn abends laut Musik hören.', "Ce qui m'agace, c'est que mes voisins écoutent de la musique forte le soir.", 'nervt,nachbarn,laut,musik'),
    ('Famille et amis', 'Wie findest du es, wenn Freunde zu spät kommen?', 'Que penses-tu quand des amis arrivent en retard ?', 'Ich finde das nicht gut, denn ich warte nicht gern.', "Je ne trouve pas ça bien, car je n'aime pas attendre.", 'finde,warte,gut'),
    ('Famille et amis', 'Sind Geschenke für dich wichtig?', 'Les cadeaux sont-ils importants pour toi ?', 'Nein, Geschenke sind mir nicht so wichtig. Eine Karte reicht mir.', 'Non, les cadeaux ne sont pas si importants pour moi. Une carte me suffit.', 'geschenke,wichtig,karte'),
    ('Famille et amis', 'Was gefällt dir an deinen Freunden besonders?', "Qu'est-ce qui te plaît particulièrement chez tes amis ?", 'Mir gefällt, dass meine Freunde so viel Humor haben.', "Ce qui me plaît, c'est que mes amis ont beaucoup d'humour.", 'gefällt,freunde,humor'),
    ('Famille et amis', 'Telefonierst du lieber mit Freunden oder schreibst du Nachrichten?', 'Préfères-tu téléphoner à des amis ou écrire des messages ?', 'Ich schreibe lieber Nachrichten, weil das billiger ist.', "Je préfère écrire des messages, parce que c'est moins cher.", 'lieber,schreibe,nachrichten,billiger'),
    ('Famille et amis', 'Bist du lieber allein oder mit Freunden?', 'Préfères-tu être seul ou avec des amis ?', 'Ich bin lieber mit Freunden zusammen, weil das mehr Spaß macht.', "Je préfère être avec des amis, parce que c'est plus amusant.", 'lieber,freunden,spaß,zusammen'),
    ('Famille et amis', 'Feierst du lieber zu Hause oder in einem Restaurant?', 'Préfères-tu faire la fête à la maison ou au restaurant ?', 'Ich feiere lieber zu Hause, denn dort ist es gemütlich.', 'Je préfère faire la fête à la maison, car on y est bien.', 'feiere,lieber,hause,gemütlich'),
    ('Famille et amis', 'Gehst du lieber zu deinen Freunden oder kommen sie zu dir?', "Préfères-tu aller chez tes amis ou qu'ils viennent chez toi ?", 'Ich gehe lieber zu meinen Freunden, weil mein Zimmer sehr klein ist.', 'Je préfère aller chez mes amis, parce que ma chambre est très petite.', 'lieber,gehe,freunden,zimmer'),
    ('Famille et amis', 'Bist du eher ruhig oder laut?', 'Es-tu plutôt calme ou bruyant(e) ?', 'Ich bin eher ruhig, aber mit meinen Freunden bin ich lustig.', 'Je suis plutôt calme, mais avec mes amis je suis drôle.', 'ruhig,lustig,eher,freunden'),
    ('Famille et amis', 'Wen rufst du zuerst an, wenn du ein Problem hast?', 'Qui appelles-tu en premier quand tu as un problème ?', 'Wenn ich ein Problem habe, rufe ich zuerst meine Mutter an.', "Quand j'ai un problème, j'appelle d'abord ma mère.", 'problem,rufe,mutter,zuerst'),
    ('Famille et amis', 'Dein Freund hat Geburtstag. Was sagst du ihm?', "C'est l'anniversaire de ton ami. Que lui dis-tu ?", 'Ich sage: Alles Gute zum Geburtstag! Ich wünsche dir viel Glück.', 'Je dis : Joyeux anniversaire ! Je te souhaite beaucoup de bonheur.', 'geburtstag,alles,gute,wünsche'),
    ('Famille et amis', 'Du besuchst Freunde. Was bringst du mit?', "Tu rends visite à des amis. Qu'apportes-tu ?", 'Ich bringe Blumen und etwas zu trinken mit.', "J'apporte des fleurs et quelque chose à boire.", 'bringe,blumen,trinken'),
    ('Famille et amis', 'Dein Nachbar ist krank. Was machst du?', 'Ton voisin est malade. Que fais-tu ?', 'Ich besuche ihn und helfe ihm beim Einkaufen.', "Je lui rends visite et je l'aide à faire les courses.", 'besuche,helfe,einkaufen'),
    ('Famille et amis', 'Dein Freund ruft dich an, aber du hast keine Zeit. Was sagst du?', "Ton ami t'appelle, mais tu n'as pas le temps. Que dis-tu ?", 'Ich sage: Es tut mir leid, ich habe jetzt keine Zeit. Ich rufe dich später an.', "Je dis : Désolé, je n'ai pas le temps maintenant. Je te rappelle plus tard.", 'zeit,leid,später,rufe'),
    ('Famille et amis', 'Du triffst einen alten Freund auf der Straße. Was sagst du?', 'Tu croises un vieil ami dans la rue. Que dis-tu ?', 'Ich sage: Hallo! Wie schön, dich zu sehen!', 'Je dis : Salut ! Quel plaisir de te voir !', 'hallo,schön,sehen'),
    ('Famille et amis', 'Deine Mutter braucht Geld. Was machst du?', "Ta mère a besoin d'argent. Que fais-tu ?", 'Ich schicke ihr sofort Geld mit Mobile Money.', "Je lui envoie tout de suite de l'argent par Mobile Money.", 'schicke,geld,mobile,money'),
    ('Famille et amis', 'Eine Freundin lädt dich zu ihrer Party ein. Was antwortest du?', "Une amie t'invite à sa fête. Que réponds-tu ?", 'Ich antworte: Danke für die Einladung! Ich komme gern.', "Je réponds : Merci pour l'invitation ! Je viens avec plaisir.", 'danke,einladung,komme,gern'),
    ('Famille et amis', 'Beschreibe bitte eine Person aus deiner Familie.', "Décris s'il te plaît une personne de ta famille.", 'Mein Cousin David ist groß und stark. Er hat einen kleinen Bart und ist sehr lustig.', 'Mon cousin David est grand et fort. Il a une petite barbe et est très drôle.', 'cousin,groß,lustig,bart'),
    ('Famille et amis', 'Beschreibe deine Nachbarin oder deinen Nachbarn.', 'Décris ta voisine ou ton voisin.', 'Meine Nachbarin ist eine ältere Frau. Sie ist sehr nett und kocht oft für uns.', 'Ma voisine est une femme âgée. Elle est très gentille et cuisine souvent pour nous.', 'nachbarin,nett,frau,kocht'),
    ('Famille et amis', 'Wer in deiner Familie ist dir am ähnlichsten?', 'Qui dans ta famille te ressemble le plus ?', 'Mein Vater ist mir am ähnlichsten. Wir sind beide ruhig und lesen gern.', "C'est mon père qui me ressemble le plus. Nous sommes tous les deux calmes et aimons lire.", 'ähnlichsten,vater,ruhig,lesen'),
    ('Famille et amis', 'Was ist das Besondere an deiner Familie?', "Qu'est-ce qui est spécial dans ta famille ?", 'Meine Familie ist sehr musikalisch. Wir singen jeden Sonntag zusammen.', 'Ma famille est très musicienne. Nous chantons ensemble tous les dimanches.', 'familie,musikalisch,singen'),
    ('Famille et amis', 'Erzähl mir von deiner Familie.', 'Parle-moi de ta famille.', 'Meine Familie kommt aus dem Westen. Wir sind fünf Personen und wohnen in Douala.', "Ma famille vient de l'Ouest. Nous sommes cinq personnes et habitons à Douala.", 'familie,kommt,wohnen,personen'),
    ('Famille et amis', 'Erzähl mir von deiner Kindheit.', 'Parle-moi de ton enfance.', 'Ich bin in einem Dorf aufgewachsen. Dort habe ich jeden Tag mit meinen Cousins gespielt.', "J'ai grandi dans un village. Là-bas, j'ai joué tous les jours avec mes cousins.", 'aufgewachsen,dorf,gespielt,cousins'),
    ('Famille et amis', 'Erzähl mir von einem schönen Familientreffen.', 'Raconte-moi une belle réunion de famille.', 'Im August haben wir uns alle im Dorf getroffen. Wir haben viel gegessen und bis spät in die Nacht getanzt.', 'En août, nous nous sommes tous retrouvés au village. Nous avons beaucoup mangé et dansé jusque tard dans la nuit.', 'getroffen,gegessen,getanzt,dorf'),
    ('Famille et amis', 'Welches Spiel hast du als Kind am liebsten gespielt?', 'À quel jeu aimais-tu le plus jouer quand tu étais enfant ?', 'Ich habe als Kind am liebsten Verstecken gespielt.', "Enfant, j'aimais surtout jouer à cache-cache.", 'spiel,verstecken,gespielt,kind'),
    ('Famille et amis', 'Wohin gehst du abends gern mit deinen Freunden?', 'Où aimes-tu aller le soir avec tes amis ?', 'Abends gehen wir gern in ein kleines Restaurant und essen gegrillten Fisch.', 'Le soir, nous aimons aller dans un petit restaurant et manger du poisson braisé.', 'abends,gern,restaurant,fisch'),
    ('Famille et amis', 'Wen hast du am Samstag auf dem Markt getroffen?', 'Qui as-tu rencontré samedi au marché ?', 'Am Samstag habe ich auf dem Markt eine alte Freundin getroffen.', "Samedi, j'ai rencontré une vieille amie au marché.", 'markt,getroffen,freundin,samstag'),
    ('Famille et amis', 'Wem hast du diese Woche geholfen?', 'À qui as-tu donné un coup de main cette semaine ?', 'Diese Woche habe ich meiner Nachbarin geholfen. Ich habe ihre Taschen getragen.', "Cette semaine, j'ai aidé ma voisine. J'ai porté ses sacs.", 'geholfen,nachbarin,taschen,getragen'),
    ('Famille et amis', 'Wem hast du heute eine Nachricht geschickt?', "À qui as-tu envoyé un message aujourd'hui ?", 'Heute habe ich meiner Schwester eine Nachricht geschickt.', "Aujourd'hui, j'ai envoyé un message à ma sœur.", 'nachricht,geschickt,schwester'),
    ('Famille et amis', 'Welchen Film hast du neulich mit deiner Familie gesehen?', 'Quel film as-tu regardé récemment avec ta famille ?', 'Wir haben einen lustigen Nollywood-Film gesehen.', 'Nous avons regardé un film nollywoodien drôle.', 'film,gesehen,lustigen,nollywood'),
    ('Famille et amis', 'Hast du schon einmal bei Freunden übernachtet?', 'As-tu déjà dormi chez des amis ?', 'Ja, ich habe oft bei einem Freund in Douala übernachtet.', "Oui, j'ai souvent dormi chez un ami à Douala.", 'übernachtet,freund,douala'),
    ('Famille et amis', 'Wen möchtest du bald wiedersehen?', 'Qui aimerais-tu revoir bientôt ?', 'Ich möchte bald meine Oma wiedersehen. Ich vermisse sie sehr.', 'Je voudrais revoir ma grand-mère bientôt. Elle me manque beaucoup.', 'möchte,wiedersehen,vermisse,oma'),
    ('Manger et boire', 'Was frühstückst du normalerweise?', 'Que prends-tu normalement au petit-déjeuner ?', 'Normalerweise frühstücke ich Brot mit Butter und trinke Tee.', 'Normalement, je prends du pain avec du beurre au petit-déjeuner et je bois du thé.', 'frühstücke,brot,tee,butter'),
    ('Manger et boire', 'Trinkst du morgens lieber Kaffee oder Tee?', 'Le matin, préfères-tu boire du café ou du thé ?', 'Morgens trinke ich lieber Tee, weil Kaffee mir nicht schmeckt.', "Le matin, je préfère boire du thé parce que je n'aime pas le goût du café.", 'tee,kaffee,trinke,lieber'),
    ('Manger et boire', 'Was ist dein Lieblingsessen?', 'Quel est ton plat préféré ?', 'Mein Lieblingsessen ist Reis mit Hähnchen und Tomatensoße.', "Mon plat préféré, c'est du riz avec du poulet et de la sauce tomate.", 'lieblingsessen,reis,hähnchen,soße'),
    ('Manger et boire', 'Isst du gern Fisch?', 'Aimes-tu manger du poisson ?', 'Ja, ich esse gern Fisch, besonders gegrillten Fisch mit Kochbananen.', "Oui, j'aime manger du poisson, surtout du poisson grillé avec des bananes plantain.", 'fisch,esse,gern,gegrillten'),
    ('Manger et boire', 'Wann isst du zu Mittag?', 'À quelle heure déjeunes-tu ?', 'Ich esse um halb eins zu Mittag, meistens mit meiner Familie.', 'Je déjeune à midi et demi, la plupart du temps avec ma famille.', 'mittag,esse,halb,familie'),
    ('Manger et boire', 'Was trinkst du gern?', "Qu'aimes-tu boire ?", 'Ich trinke gern Wasser und manchmal Orangensaft.', "J'aime boire de l'eau et parfois du jus d'orange.", 'trinke,wasser,saft,gern'),
    ('Manger et boire', 'Magst du Schokolade?', 'Aimes-tu le chocolat ?', 'Ja, ich mag Schokolade sehr, aber ich esse sie nicht jeden Tag.', "Oui, j'aime beaucoup le chocolat, mais je n'en mange pas tous les jours.", 'schokolade,mag,esse'),
    ('Manger et boire', 'Welches Obst magst du am liebsten?', 'Quel fruit préfères-tu ?', 'Ich mag Mangos am liebsten, weil sie so süß sind.', "J'aime les mangues par-dessus tout, parce qu'elles sont si sucrées.", 'mango,süß,mag,liebsten'),
    ('Manger et boire', 'Wo isst du zu Abend?', 'Où dînes-tu ?', 'Ich esse zu Hause zu Abend, meistens in der Küche.', 'Je dîne à la maison, la plupart du temps dans la cuisine.', 'abend,hause,küche,esse'),
    ('Manger et boire', 'Wie viele Mahlzeiten isst du am Tag?', 'Combien de repas manges-tu par jour ?', 'Ich esse drei Mahlzeiten am Tag: Frühstück, Mittagessen und Abendessen.', 'Je prends trois repas par jour : le petit-déjeuner, le déjeuner et le dîner.', 'mahlzeiten,drei,frühstück,mittagessen'),
    ('Manger et boire', 'Isst du lieber Reis oder Kartoffeln?', 'Préfères-tu manger du riz ou des pommes de terre ?', 'Ich esse lieber Reis, denn Reis schmeckt mir besser.', 'Je préfère manger du riz, car le riz me plaît davantage.', 'reis,lieber,schmeckt,besser'),
    ('Manger et boire', 'Welches Gemüse isst du gern?', 'Quels légumes aimes-tu manger ?', 'Ich esse gern Tomaten, Karotten und Spinat.', "J'aime manger des tomates, des carottes et des épinards.", 'tomaten,karotten,spinat,esse'),
    ('Manger et boire', 'Trinkst du viel Wasser?', "Bois-tu beaucoup d'eau ?", 'Ja, ich trinke jeden Tag ungefähr zwei Liter Wasser.', "Oui, je bois environ deux litres d'eau chaque jour.", 'wasser,trinke,liter,tag'),
    ('Manger et boire', 'Was kochst du heute Abend?', 'Que cuisines-tu ce soir ?', 'Heute Abend koche ich Nudeln mit Tomatensoße.', 'Ce soir, je cuisine des pâtes avec de la sauce tomate.', 'abend,koche,nudeln,tomatensoße'),
    ('Manger et boire', 'Kochst du gern?', 'Aimes-tu cuisiner ?', 'Ja, ich koche gern, besonders am Wochenende.', "Oui, j'aime cuisiner, surtout le week-end.", 'koche,gern,wochenende'),
    ('Manger et boire', 'Was ist dein Lieblingsgetränk?', 'Quelle est ta boisson préférée ?', 'Mein Lieblingsgetränk ist kalter Ananassaft.', "Ma boisson préférée est le jus d'ananas bien frais.", 'lieblingsgetränk,ananassaft,kalt'),
    ('Manger et boire', 'Magst du scharfes Essen?', 'Aimes-tu la nourriture épicée ?', 'Nein, scharfes Essen mag ich nicht, es brennt zu stark im Mund.', "Non, je n'aime pas la nourriture épicée, ça brûle trop dans la bouche.", 'scharfes,mag,essen,brennt'),
    ('Manger et boire', 'Hast du jetzt Hunger?', 'As-tu faim maintenant ?', 'Ja, ich habe großen Hunger, denn ich habe noch nichts gegessen.', "Oui, j'ai très faim, car je n'ai encore rien mangé.", 'hunger,habe,gegessen'),
    ('Manger et boire', 'Isst du oft Fleisch?', 'Manges-tu souvent de la viande ?', 'Ich esse zweimal pro Woche Fleisch, meistens Hähnchen oder Rindfleisch.', 'Je mange de la viande deux fois par semaine, le plus souvent du poulet ou du bœuf.', 'fleisch,esse,hähnchen,woche'),
    ('Manger et boire', 'Welches Gericht hast du zuletzt im Restaurant bestellt?', 'Quel plat as-tu commandé la dernière fois au restaurant ?', 'Zuletzt habe ich im Restaurant Fisch mit Gemüse bestellt.', "La dernière fois, j'ai commandé du poisson avec des légumes au restaurant.", 'restaurant,bestellt,zuletzt,fisch'),
    ('Manger et boire', 'Isst du gern Eis?', 'Aimes-tu manger de la glace ?', 'Ja, wenn es heiß ist, esse ich sehr gern Eis, am liebsten Vanilleeis.', "Oui, quand il fait chaud, j'aime beaucoup manger de la glace, surtout à la vanille.", 'eis,esse,heiß,vanilleeis'),
    ('Manger et boire', 'Was kaufst du auf dem Markt?', "Qu'achètes-tu au marché ?", 'Auf dem Markt kaufe ich frisches Gemüse, Obst und Fisch.', "Au marché, j'achète des légumes frais, des fruits et du poisson.", 'markt,kaufe,gemüse,obst'),
    ('Manger et boire', 'Hast du heute Morgen Milch getrunken?', 'As-tu bu du lait ce matin ?', 'Nein, ich habe heute Morgen keine Milch getrunken, sondern nur Tee.', "Non, ce matin je n'ai pas bu de lait, seulement du thé.", 'milch,getrunken,tee,morgen'),
    ('Manger et boire', 'Was gab es gestern bei dir zum Mittagessen?', "Qu'y avait-il hier chez toi pour le déjeuner ?", 'Gestern gab es bei uns Spaghetti mit Tomaten und Ei.', 'Hier, chez nous, il y avait des spaghettis avec des tomates et un œuf.', 'gestern,gab,spaghetti,tomaten'),
    ('Manger et boire', 'Was isst du am Wochenende gern?', "Qu'aimes-tu manger le week-end ?", 'Am Wochenende esse ich gern Fufu mit Gemüsesoße.', "Le week-end, j'aime manger du fufu avec une sauce aux légumes.", 'wochenende,fufu,esse,gern'),
    ('Manger et boire', 'Hast du einen Kühlschrank zu Hause?', 'As-tu un réfrigérateur à la maison ?', 'Ja, wir haben einen Kühlschrank in der Küche.', 'Oui, nous avons un réfrigérateur dans la cuisine.', 'kühlschrank,haben,küche'),
    ('Manger et boire', 'Was liegt bei dir im Kühlschrank?', "Qu'y a-t-il dans ton réfrigérateur ?", 'Bei mir liegen im Kühlschrank Wasser, Eier und etwas Gemüse.', "Chez moi, il y a de l'eau, des œufs et un peu de légumes dans le réfrigérateur.", 'kühlschrank,wasser,eier,gemüse'),
    ('Manger et boire', 'Wie findest du das Essen in der Schule oder bei der Arbeit?', "Comment trouves-tu la nourriture à l'école ou au travail ?", 'Ich finde das Essen in der Schule nicht besonders gut, weil es oft kalt ist.', "Je ne trouve pas la nourriture à l'école très bonne, parce qu'elle est souvent froide.", 'finde,essen,schule,kalt'),
    ('Manger et boire', 'Wie schmeckt eine Zitrone?', 'Quel goût a un citron ?', 'Eine Zitrone schmeckt sehr sauer.', 'Un citron a un goût très acide.', 'zitrone,sauer,schmeckt'),
    ('Manger et boire', 'Was isst du normalerweise in der Pause?', 'Que manges-tu normalement pendant la pause ?', 'Normalerweise esse ich in der Pause ein Sandwich und eine Banane.', 'Normalement, pendant la pause, je mange un sandwich et une banane.', 'pause,sandwich,banane,esse'),
    ('Manger et boire', 'Welche Suppe magst du?', 'Quelle soupe aimes-tu ?', 'Ich mag Hühnersuppe, besonders wenn es regnet.', "J'aime la soupe de poulet, surtout quand il pleut.", 'hühnersuppe,suppe,mag,regnet'),
    ('Manger et boire', 'Was trinkst du, wenn du Durst hast?', 'Que bois-tu quand tu as soif ?', 'Wenn ich Durst habe, trinke ich kaltes Wasser.', "Quand j'ai soif, je bois de l'eau fraîche.", 'durst,trinke,wasser,kaltes'),
    ('Manger et boire', 'Wann hast du zuletzt Süßigkeiten gegessen?', 'Quand as-tu mangé des sucreries pour la dernière fois ?', 'Ich habe gestern Abend Süßigkeiten gegessen, weil ich Lust darauf hatte.', "Hier soir, j'ai mangé des sucreries parce que j'en avais envie.", 'süßigkeiten,gestern,gegessen,lust'),
    ('Manger et boire', 'Isst du lieber salzig oder süß?', 'Préfères-tu le salé ou le sucré ?', 'Ich esse lieber salzig, zum Beispiel Chips oder Erdnüsse.', 'Je préfère le salé, par exemple des chips ou des cacahuètes.', 'salzig,lieber,erdnüsse,chips'),
    ('Manger et boire', 'Wie schmeckt dein Lieblingsessen?', 'Quel goût a ton plat préféré ?', 'Mein Lieblingsessen schmeckt würzig und ein bisschen scharf.', 'Mon plat préféré a un goût relevé et un peu épicé.', 'schmeckt,würzig,scharf,lieblingsessen'),
    ('Manger et boire', 'Kannst du gut kochen?', 'Sais-tu bien cuisiner ?', 'Ich kann gut kochen, zum Beispiel Nudeln und Reis mit Soße.', 'Je sais bien cuisiner, par exemple des pâtes et du riz avec de la sauce.', 'kann,kochen,nudeln,soße'),
    ('Manger et boire', 'Trinkst du Tee mit Zucker?', 'Bois-tu ton thé avec du sucre ?', 'Ja, ich trinke Tee mit viel Zucker, ich mag es süß.', "Oui, je bois mon thé avec beaucoup de sucre, j'aime que ce soit sucré.", 'tee,zucker,trinke,süß'),
    ('Manger et boire', 'Was findest du am Essen in Kamerun besonders gut?', "Qu'est-ce que tu trouves particulièrement bien dans la cuisine camerounaise ?", 'Ich finde die vielen frischen Zutaten besonders gut, zum Beispiel Obst und Gemüse vom Markt.', 'Je trouve particulièrement bien les nombreux ingrédients frais, par exemple les fruits et légumes du marché.', 'finde,frischen,zutaten,obst'),
    ('Manger et boire', 'Was gibt es bei dir meistens zum Mittagessen?', "Qu'y a-t-il le plus souvent chez toi pour le déjeuner ?", 'Bei mir gibt es meistens Bohnen mit gebratenen Kochbananen.', 'Chez moi, il y a le plus souvent des haricots avec des bananes plantain frites.', 'gibt,bohnen,kochbananen,meistens'),
    ('Manger et boire', 'Was hast du heute zum Frühstück gegessen?', "Qu'as-tu mangé ce matin au petit-déjeuner ?", 'Heute habe ich Brot mit Ei gegessen und einen Tee getrunken.', "Aujourd'hui, j'ai mangé du pain avec un œuf et bu un thé.", 'gegessen,heute,brot,tee'),
    ('Manger et boire', 'Was hast du gestern zu Abend gegessen?', "Qu'as-tu mangé hier soir au dîner ?", 'Gestern habe ich Kartoffeln mit Gemüse und Fleisch gegessen.', "Hier, j'ai mangé des pommes de terre avec des légumes et de la viande.", 'gestern,gegessen,kartoffeln,gemüse'),
    ('Manger et boire', 'Hast du heute schon etwas getrunken?', "As-tu déjà bu quelque chose aujourd'hui ?", 'Ja, ich habe heute schon zwei Gläser Wasser und einen Kaffee getrunken.', "Oui, j'ai déjà bu aujourd'hui deux verres d'eau et un café.", 'getrunken,wasser,kaffee,heute'),
    ('Manger et boire', 'Was möchtest du heute Abend essen?', 'Que voudrais-tu manger ce soir ?', 'Heute Abend möchte ich Reis mit Bohnen essen.', 'Ce soir, je voudrais manger du riz avec des haricots.', 'möchte,essen,reis,bohnen'),
    ('Manger et boire', 'Warum isst du gern Obst?', 'Pourquoi aimes-tu manger des fruits ?', 'Ich esse gern Obst, weil es gesund ist und gut schmeckt.', "J'aime manger des fruits parce que c'est sain et que c'est bon.", 'obst,gesund,weil,schmeckt'),
    ('Manger et boire', 'Warum trinken viele Leute morgens Kaffee?', 'Pourquoi beaucoup de gens boivent-ils du café le matin ?', 'Viele Leute trinken morgens Kaffee, weil sie wach werden möchten.', "Beaucoup de gens boivent du café le matin parce qu'ils veulent se réveiller.", 'kaffee,wach,morgens,weil'),
    ('Manger et boire', 'Du bist im Restaurant. Was bestellst du?', 'Tu es au restaurant. Que commandes-tu ?', 'Ich hätte gern eine Pizza mit Käse und ein Glas Wasser, bitte.', "Je voudrais une pizza au fromage et un verre d'eau, s'il vous plaît.", 'hätte,pizza,käse,wasser'),
    ('Manger et boire', 'Der Kellner fragt: Was möchten Sie trinken?', 'Le serveur demande : que désirez-vous boire ?', 'Ich möchte bitte eine Flasche Mineralwasser.', "Je voudrais une bouteille d'eau minérale, s'il vous plaît.", 'möchte,flasche,mineralwasser,bitte'),
    ('Manger et boire', 'Wie bezahlst du im Restaurant: bar oder mit Mobile Money?', 'Comment paies-tu au restaurant : en espèces ou avec Mobile Money ?', 'Ich bezahle meistens bar, manchmal mit Mobile Money.', 'Je paie le plus souvent en espèces, parfois avec Mobile Money.', 'bezahle,bar,mobile,money'),
    ('Manger et boire', 'Wo isst du morgen zu Mittag?', 'Où déjeunes-tu demain ?', 'Morgen esse ich mit meinen Kollegen in der Kantine.', 'Demain, je mange à la cantine avec mes collègues.', 'morgen,kantine,kollegen,esse'),
    ('Manger et boire', 'Was kochst du am Sonntag für deine Familie?', 'Que cuisines-tu dimanche pour ta famille ?', 'Am Sonntag koche ich einen großen Topf Gemüsesuppe für meine Familie.', 'Le dimanche, je prépare une grande marmite de soupe de légumes pour ma famille.', 'sonntag,koche,gemüsesuppe,familie'),
    ('Manger et boire', 'Welches Essen kochst du am besten?', 'Quel plat cuisines-tu le mieux ?', 'Am besten koche ich Pfannkuchen, das habe ich von meiner Oma gelernt.', "Ce que je cuisine le mieux, ce sont les crêpes, je l'ai appris de ma grand-mère.", 'koche,pfannkuchen,oma,gelernt'),
    ('Manger et boire', 'Was brauchst du für einen Obstsalat?', 'De quoi as-tu besoin pour une salade de fruits ?', 'Für einen Obstsalat brauche ich Bananen, Ananas, Orangen und etwas Zucker.', "Pour une salade de fruits, j'ai besoin de bananes, d'ananas, d'oranges et d'un peu de sucre.", 'obstsalat,bananen,ananas,orangen'),
    ('Manger et boire', 'Wie machst du Rührei?', 'Comment fais-tu des œufs brouillés ?', 'Zuerst schlage ich die Eier in eine Schüssel, dann brate ich sie in der Pfanne.', "D'abord, je casse les œufs dans un bol, puis je les fais cuire à la poêle.", 'eier,pfanne,brate,zuerst'),
    ('Manger et boire', 'Wie kochst du Reis?', 'Comment cuis-tu le riz ?', 'Ich koche den Reis zwanzig Minuten in Wasser mit etwas Salz.', "Je cuis le riz vingt minutes dans de l'eau avec un peu de sel.", 'reis,wasser,minuten,salz'),
    ('Manger et boire', 'Welche Gewürze benutzt du beim Kochen?', 'Quelles épices utilises-tu en cuisinant ?', 'Ich benutze oft Salz, Pfeffer, Knoblauch und Zwiebeln.', "J'utilise souvent du sel, du poivre, de l'ail et des oignons.", 'salz,pfeffer,knoblauch,benutze'),
    ('Manger et boire', 'Isst du lieber zu Hause oder im Restaurant?', 'Préfères-tu manger à la maison ou au restaurant ?', 'Ich esse lieber zu Hause, weil das billiger ist und besser schmeckt.', "Je préfère manger à la maison, parce que c'est moins cher et meilleur.", 'lieber,hause,billiger,weil'),
    ('Manger et boire', 'Gehst du oft in ein Café?', 'Vas-tu souvent dans un café ?', 'Ja, ich gehe einmal pro Woche mit Freunden in ein Café.', 'Oui, je vais une fois par semaine dans un café avec des amis.', 'café,gehe,freunden,woche'),
    ('Manger et boire', 'Was bestellst du im Café?', 'Que commandes-tu au café ?', 'Im Café bestelle ich einen Kaffee mit Milch und ein Stück Kuchen.', 'Au café, je commande un café au lait et une part de gâteau.', 'café,bestelle,kaffee,kuchen'),
    ('Manger et boire', 'Welchen Kuchen magst du am liebsten?', 'Quel gâteau préfères-tu ?', 'Ich mag Schokoladenkuchen am liebsten, vor allem mit Sahne.', "J'aime surtout le gâteau au chocolat, notamment avec de la crème.", 'kuchen,schokoladenkuchen,sahne,mag'),
    ('Manger et boire', 'Wenn du krank bist: Was isst du dann?', 'Quand tu es malade : que manges-tu alors ?', 'Wenn ich krank bin, esse ich nur Suppe und Brot.', 'Quand je suis malade, je mange seulement de la soupe et du pain.', 'krank,suppe,brot,esse'),
    ('Manger et boire', 'Was isst du auf keinen Fall?', 'Que ne manges-tu en aucun cas ?', 'Auf keinen Fall esse ich rohen Fisch, weil ich ihn eklig finde.', 'En aucun cas je ne mange de poisson cru, parce que je trouve ça dégoûtant.', 'keinen,rohen,fisch,eklig'),
    ('Manger et boire', 'Wie findest du Fast Food?', 'Que penses-tu de la restauration rapide ?', 'Ich finde Fast Food nicht gesund, aber es ist schnell und billig.', "Je trouve que la restauration rapide n'est pas saine, mais elle est rapide et bon marché.", 'fast,gesund,schnell,finde'),
    ('Manger et boire', 'Welche Mahlzeit ist für dich die wichtigste?', 'Quel repas est le plus important pour toi ?', 'Für mich ist das Frühstück die wichtigste Mahlzeit, weil ich morgens viel Energie brauche.', "Pour moi, le petit-déjeuner est le repas le plus important, parce que j'ai besoin de beaucoup d'énergie le matin.", 'wichtigste,frühstück,energie,weil'),
    ('Manger et boire', 'Isst du Fufu lieber mit den Händen oder mit der Gabel?', 'Manges-tu le fufu plutôt avec les mains ou avec la fourchette ?', 'Ich esse Fufu lieber mit den Händen, so schmeckt es besser.', "Je préfère manger le fufu avec les mains, c'est meilleur comme ça.", 'fufu,händen,lieber,schmeckt'),
    ('Manger et boire', 'Was trinkst du zum Essen?', 'Que bois-tu pendant le repas ?', 'Zum Essen trinke ich meistens Wasser, manchmal auch Limonade.', "Pendant le repas, je bois le plus souvent de l'eau, parfois aussi de la limonade.", 'trinke,wasser,limonade,meistens'),
    ('Manger et boire', 'Hast du schon einmal Sauerkraut gegessen?', 'As-tu déjà mangé de la choucroute ?', 'Nein, ich habe noch nie Sauerkraut gegessen, aber ich möchte es probieren.', "Non, je n'ai jamais mangé de choucroute, mais j'aimerais l'essayer.", 'sauerkraut,nie,gegessen,probieren'),
    ('Manger et boire', 'Was willst du morgen einkaufen?', "Qu'est-ce que tu veux acheter demain ?", 'Morgen will ich Öl, Tomaten und frisches Obst einkaufen.', "Demain, je veux acheter de l'huile, des tomates et des fruits frais.", 'morgen,einkaufen,tomaten,obst'),
    ('Manger et boire', 'Auf dem Markt: Was hast du letzte Woche gekauft?', "Au marché : qu'as-tu acheté la semaine dernière ?", 'Letzte Woche habe ich Tomaten, Zwiebeln und einen großen Fisch gekauft.', "La semaine dernière, j'ai acheté des tomates, des oignons et un gros poisson.", 'gekauft,tomaten,zwiebeln,fisch'),
    ('Manger et boire', 'Wie viel kostet ein Kilo Tomaten bei dir?', 'Combien coûte un kilo de tomates chez toi ?', 'Ein Kilo Tomaten kostet bei uns ungefähr tausend Franc.', 'Un kilo de tomates coûte chez nous environ mille francs.', 'kilo,kostet,tomaten,franc'),
    ('Manger et boire', 'Wo hast du dein Brot heute gekauft?', "Où as-tu acheté ton pain aujourd'hui ?", 'Ich habe mein Brot heute in der Bäckerei an der Ecke gekauft.', "J'ai acheté mon pain aujourd'hui à la boulangerie du coin.", 'brot,gekauft,bäckerei,ecke'),
    ('Manger et boire', 'Willst du heute Abend essen gehen?', 'Veux-tu sortir manger ce soir ?', 'Ja, gern! Wir können in das Restaurant neben dem Markt gehen.', 'Oui, volontiers ! Nous pouvons aller au restaurant à côté du marché.', 'gern,restaurant,gehen,markt'),
    ('Manger et boire', 'Wie lange hast du gestern gekocht?', 'Combien de temps as-tu cuisiné hier ?', 'Gestern habe ich fast zwei Stunden gekocht, weil wir Besuch hatten.', "Hier, j'ai cuisiné presque deux heures parce que nous avions de la visite.", 'gekocht,gestern,stunden,besuch'),
    ('Manger et boire', 'Mit deinen Freunden: Was isst du am liebsten?', 'Que préfères-tu manger avec tes amis ?', 'Mit meinen Freunden esse ich am liebsten gegrillte Fleischspieße.', 'Avec mes amis, ce que je préfère manger, ce sont des brochettes de viande grillées.', 'freunden,gegrillte,fleischspieße,liebsten'),
    ('Manger et boire', 'Welches Essen gab es an deinem letzten Geburtstag?', "Qu'y avait-il à manger pour ton dernier anniversaire ?", 'An meinem letzten Geburtstag gab es Torte und Reis mit Hähnchen.', 'Pour mon dernier anniversaire, il y avait un gâteau et du riz avec du poulet.', 'geburtstag,torte,hähnchen,gab'),
    ('Manger et boire', 'Du hast Besuch. Was bietest du deinen Gästen an?', 'Tu as de la visite. Que proposes-tu à tes invités ?', 'Ich biete meinen Gästen Tee, Kekse und frisches Obst an.', 'Je propose à mes invités du thé, des biscuits et des fruits frais.', 'biete,gästen,tee,kekse'),
    ('Manger et boire', 'Was möchtest du gern kochen oder backen lernen?', "Qu'aimerais-tu apprendre à cuisiner ou à faire cuire au four ?", 'Ich möchte gern lernen, Brot zu backen.', "J'aimerais apprendre à faire du pain.", 'lernen,backen,brot,möchte'),
    ('Manger et boire', 'Was ist gesünder: Obst oder Pommes?', "Qu'est-ce qui est plus sain : les fruits ou les frites ?", 'Obst ist gesünder als Pommes, aber ich esse trotzdem manchmal Pommes.', 'Les fruits sont plus sains que les frites, mais je mange quand même parfois des frites.', 'gesünder,obst,pommes,trotzdem'),
    ('Manger et boire', 'Wann trinkst du Tee?', 'Quand bois-tu du thé ?', 'Ich trinke Tee am Nachmittag und am Abend, wenn es kühl ist.', "Je bois du thé l'après-midi et le soir, quand il fait frais.", 'tee,nachmittag,abend,trinke'),
    ('Manger et boire', 'Erzähl mir von deinem Lieblingsrestaurant.', 'Parle-moi de ton restaurant préféré.', 'Mein Lieblingsrestaurant ist klein und liegt in der Nähe vom Markt. Dort ist das Essen frisch und nicht teuer.', 'Mon restaurant préféré est petit et se trouve près du marché. Là-bas, la nourriture est fraîche et pas chère.', 'lieblingsrestaurant,nähe,frisch,teuer'),
    ('Manger et boire', 'Erzähl mir von einem typischen Essen in deinem Land.', "Parle-moi d'un plat typique de ton pays.", 'Bei uns in Kamerun isst man gern Ndolé. Das ist ein Gericht mit Erdnüssen und Fleisch oder Fisch.', "Chez nous au Cameroun, on mange volontiers du ndolé. C'est un plat avec des cacahuètes et de la viande ou du poisson.", 'kamerun,ndolé,gericht,erdnüssen'),
    ('Manger et boire', 'Warum ist gesundes Essen wichtig für dich?', 'Pourquoi manger sainement est-il important pour toi ?', 'Gesundes Essen ist mir wichtig, weil ich viel arbeite und fit bleiben möchte.', 'Manger sainement est important pour moi, parce que je travaille beaucoup et que je veux rester en forme.', 'gesundes,wichtig,fit,weil'),
    ('Manger et boire', 'Was würdest du gern einmal probieren?', "Qu'aimerais-tu goûter un jour ?", 'Ich würde gern einmal richtige Bratwurst mit Senf probieren.', "J'aimerais goûter une fois une vraie saucisse grillée avec de la moutarde.", 'würde,probieren,bratwurst,senf'),
    ('Manger et boire', 'Wie unterscheidet sich das Essen in Kamerun vom Essen in Deutschland?', 'En quoi la nourriture au Cameroun est-elle différente de celle en Allemagne ?', 'In Kamerun essen wir mehr Reis, Maniok und scharfe Soßen. In Deutschland isst man viel Brot und Kartoffeln.', 'Au Cameroun, nous mangeons plus de riz, de manioc et de sauces pimentées. En Allemagne, on mange beaucoup de pain et de pommes de terre.', 'kamerun,deutschland,brot,soßen'),
    ('Manger et boire', 'Was glaubst du: Was essen die Deutschen zum Frühstück?', 'Que crois-tu : que mangent les Allemands au petit-déjeuner ?', 'Ich glaube, die Deutschen essen zum Frühstück Brötchen mit Wurst, Käse oder Marmelade.', 'Je crois que les Allemands mangent au petit-déjeuner des petits pains avec de la charcuterie, du fromage ou de la confiture.', 'deutschen,brötchen,wurst,marmelade'),
    ('Manger et boire', 'Kochst du meistens selbst oder isst du oft auswärts?', 'Cuisines-tu surtout toi-même ou manges-tu souvent dehors ?', 'Ich koche meistens selbst, denn das ist billiger und gesünder.', "Je cuisine surtout moi-même, car c'est moins cher et plus sain.", 'koche,selbst,billiger,gesünder'),
    ('Manger et boire', 'Wie war dein letzter Restaurantbesuch?', "Comment s'est passée ta dernière visite au restaurant ?", 'Er war sehr schön. Ich habe mit Freunden Fisch gegessen, und das Essen war lecker, aber ein bisschen teuer.', "C'était très bien. J'ai mangé du poisson avec des amis, et le repas était bon, mais un peu cher.", 'freunden,gegessen,lecker,teuer'),
    ('Manger et boire', 'Was machst du, wenn du keine Lust auf Kochen hast?', "Que fais-tu quand tu n'as pas envie de cuisiner ?", 'Wenn ich keine Lust zum Kochen habe, kaufe ich gegrilltes Fleisch an der Straße.', "Quand je n'ai pas envie de cuisiner, j'achète de la viande grillée dans la rue.", 'lust,kaufe,gegrilltes,straße'),
    ('Manger et boire', 'Was war dein Lieblingsessen als Kind?', 'Quel était ton plat préféré quand tu étais enfant ?', 'Als Kind war mein Lieblingsessen gekochte Süßkartoffel. Meine Oma hat sie oft für mich gemacht.', "Enfant, mon plat préféré était la patate douce cuite. Ma grand-mère m'en faisait souvent.", 'kind,lieblingsessen,süßkartoffel,oma'),
    ('Manger et boire', 'Wie wichtig ist dir das Essen mit der Familie?', 'Quelle importance a pour toi le repas en famille ?', 'Das Essen mit meiner Familie ist mir sehr wichtig, denn dann sprechen wir über den Tag.', 'Le repas avec ma famille est très important pour moi, car nous parlons alors de notre journée.', 'familie,wichtig,sprechen,essen'),
    ('Manger et boire', 'Welches Essen aus deiner Heimat würdest du in Deutschland vermissen?', 'Quel plat de ton pays te manquerait en Allemagne ?', 'Ich würde die scharfen Soßen und die frischen Mangos aus meiner Heimat vermissen.', 'Les sauces pimentées et les mangues fraîches de mon pays me manqueraient.', 'vermissen,würde,soßen,mangos'),
    ('Manger et boire', 'Wie bereitest du dich auf ein großes Familienfest vor?', 'Comment te prépares-tu pour une grande fête de famille ?', 'Zuerst gehe ich auf den Markt und kaufe viel Fleisch und Gemüse. Dann koche ich mit meiner Familie zusammen.', "D'abord, je vais au marché et j'achète beaucoup de viande et de légumes. Ensuite, je cuisine avec ma famille.", 'markt,kaufe,koche,familie'),
    ('Manger et boire', 'Beschreibe einen Markt in deiner Stadt.', 'Décris un marché de ta ville.', 'Der Markt in Yaoundé ist groß und laut. Es gibt dort Obst, Gemüse, Fisch und Fleisch, und man kann handeln.', 'Le marché de Yaoundé est grand et bruyant. On y trouve des fruits, des légumes, du poisson et de la viande, et on peut marchander.', 'markt,yaoundé,gemüse,handeln'),
    ('Manger et boire', 'Was machst du, um gesund zu essen?', 'Que fais-tu pour manger sainement ?', 'Um gesund zu essen, esse ich viel Gemüse und Obst und trinke wenig Limonade.', 'Pour manger sainement, je mange beaucoup de légumes et de fruits et je bois peu de limonade.', 'gesund,gemüse,obst,limonade'),
    ('Manger et boire', 'Machst du manchmal eine Diät?', 'Fais-tu parfois un régime ?', 'Nein, ich mache keine Diät, aber ich esse abends weniger.', 'Non, je ne fais pas de régime, mais je mange moins le soir.', 'diät,weniger,abends,esse'),
    ('Manger et boire', 'Welches Gewürz darf in deiner Küche nie fehlen?', 'Quelle épice ne doit jamais manquer dans ta cuisine ?', 'Ingwer darf in meiner Küche nie fehlen, weil er dem Tee und der Soße einen guten Geschmack gibt.', "Le gingembre ne doit jamais manquer dans ma cuisine, parce qu'il donne bon goût au thé et à la sauce.", 'ingwer,fehlen,geschmack,tee'),
    ('Manger et boire', 'Was gibt es bei einer Hochzeit in deiner Familie zu essen?', "Que mange-t-on lors d'un mariage dans ta famille ?", 'Bei einer Hochzeit gibt es viel Fleisch, Reis, Salat und natürlich einen großen Kuchen.', "Lors d'un mariage, il y a beaucoup de viande, du riz, de la salade et bien sûr un grand gâteau.", 'hochzeit,gibt,fleisch,kuchen'),
    ('Manger et boire', 'Erzähl mir ein einfaches Rezept für einen Salat.', 'Donne-moi une recette simple de salade.', 'Ich schneide Tomaten, Gurken und Zwiebeln, mische alles mit Öl und Zitronensaft und gebe etwas Salz dazu.', "Je coupe des tomates, des concombres et des oignons, je mélange tout avec de l'huile et du jus de citron et j'ajoute un peu de sel.", 'tomaten,gurken,zitronensaft,schneide'),
    ('Manger et boire', 'Was ist deine schönste Erinnerung an ein Essen?', 'Quel est ton plus beau souvenir lié à un repas ?', 'Meine schönste Erinnerung ist ein großes Essen bei meiner Großmutter, wo die ganze Familie zusammen war.', 'Mon plus beau souvenir est un grand repas chez ma grand-mère, où toute la famille était réunie.', 'erinnerung,großmutter,familie,essen'),
    ('Manger et boire', 'Welches Getränk ist in Kamerun beliebt?', 'Quelle boisson est populaire au Cameroun ?', 'In Kamerun ist Bissap sehr beliebt, das ist ein kalter Tee aus roten Blüten.', "Au Cameroun, le bissap est très populaire, c'est un thé froid fait de fleurs rouges.", 'bissap,beliebt,kamerun,tee'),
    ('La maison', 'Wo wohnst du?', 'Où habites-tu ?', 'Ich wohne in Yaoundé, in der Nähe vom Zentrum.', "J'habite à Yaoundé, près du centre.", 'wohne,yaoundé,nähe'),
    ('La maison', 'Wohnst du in einer Wohnung oder in einem Haus?', 'Habites-tu dans un appartement ou dans une maison ?', 'Ich wohne in einem kleinen Haus mit meiner Familie.', "J'habite dans une petite maison avec ma famille.", 'wohne,haus,familie'),
    ('La maison', 'Wie viele Zimmer hat dein Haus?', 'Combien de pièces a ta maison ?', 'Mein Haus hat vier Zimmer: zwei Schlafzimmer, ein Wohnzimmer und eine Küche.', 'Ma maison a quatre pièces : deux chambres, un salon et une cuisine.', 'zimmer,schlafzimmer,wohnzimmer,küche'),
    ('La maison', 'Was ist dein Lieblingszimmer?', 'Quelle est ta pièce préférée ?', 'Mein Lieblingszimmer ist das Wohnzimmer, weil dort das Sofa steht.', "Ma pièce préférée est le salon, parce que le canapé s'y trouve.", 'lieblingszimmer,wohnzimmer,sofa'),
    ('La maison', 'Hast du ein eigenes Zimmer?', 'As-tu ta propre chambre ?', 'Ja, ich habe ein eigenes Zimmer. Es ist klein, aber gemütlich.', "Oui, j'ai ma propre chambre. Elle est petite mais agréable.", 'eigenes,zimmer,klein,gemütlich'),
    ('La maison', 'Was steht in deinem Schlafzimmer?', "Qu'y a-t-il dans ta chambre ?", 'In meinem Schlafzimmer stehen ein Bett, ein Schrank und ein kleiner Tisch.', 'Dans ma chambre, il y a un lit, une armoire et une petite table.', 'schlafzimmer,bett,schrank,tisch'),
    ('La maison', 'Wie ist deine Küche?', 'Comment est ta cuisine ?', 'Meine Küche ist nicht groß, aber ich koche dort jeden Tag.', "Ma cuisine n'est pas grande, mais j'y cuisine tous les jours.", 'küche,groß,koche'),
    ('La maison', 'Wie findest du Putzen: langweilig oder entspannend?', 'Que penses-tu du ménage : ennuyeux ou relaxant ?', 'Ich finde Putzen ziemlich langweilig, aber danach fühle ich mich gut.', 'Je trouve le ménage plutôt ennuyeux, mais après je me sens bien.', 'putzen,langweilig,fühle'),
    ('La maison', 'Wer putzt bei euch zu Hause das Bad?', 'Qui nettoie la salle de bain chez vous ?', 'Bei uns putzt meistens meine Schwester das Bad.', "Chez nous, c'est le plus souvent ma sœur qui nettoie la salle de bain.", 'putzt,bad,schwester'),
    ('La maison', 'Hast du gestern im Haushalt geholfen?', 'As-tu aidé hier dans les tâches ménagères ?', 'Ja, ich habe gestern die Wäsche gewaschen und das Wohnzimmer aufgeräumt.', "Oui, hier j'ai lavé le linge et rangé le salon.", 'gewaschen,wäsche,aufgeräumt'),
    ('La maison', 'Welche Aufgaben hast du im Haushalt?', 'Quelles tâches as-tu dans le ménage ?', 'Ich spüle das Geschirr und wasche am Wochenende meine Wäsche.', 'Je fais la vaisselle et je lave mon linge le week-end.', 'spüle,geschirr,wasche,wäsche'),
    ('La maison', 'Bist du ordentlich oder chaotisch?', 'Es-tu ordonné ou chaotique ?', 'Ich bin eher ordentlich, denn ich mag keine Unordnung.', "Je suis plutôt ordonné, car je n'aime pas le désordre.", 'ordentlich,unordnung,mag'),
    ('La maison', 'Warum ist Ordnung zu Hause wichtig?', "Pourquoi l'ordre à la maison est-il important ?", 'Ich finde Ordnung wichtig, weil ich dann alles schnell finde.', "Je trouve l'ordre important, parce que je trouve tout vite.", 'ordnung,wichtig,finde,schnell'),
    ('La maison', 'Wie viel Miete zahlst du im Monat?', 'Combien de loyer paies-tu par mois ?', 'Ich zahle etwa fünfzigtausend Franc CFA Miete im Monat.', 'Je paie environ cinquante mille francs CFA de loyer par mois.', 'miete,zahle,franc,monat'),
    ('La maison', 'Ist die Miete in deiner Stadt teuer?', 'Le loyer est-il cher dans ta ville ?', 'Ja, in Douala ist die Miete ziemlich teuer, besonders im Zentrum.', 'Oui, à Douala le loyer est assez cher, surtout au centre.', 'miete,teuer,douala,zentrum'),
    ('La maison', 'Bezahlst du deine Miete bar oder mit Mobile Money?', 'Paies-tu ton loyer en espèces ou par Mobile Money ?', 'Ich bezahle meine Miete mit Mobile Money, das ist schnell und sicher.', "Je paie mon loyer par Mobile Money, c'est rapide et sûr.", 'miete,mobile,money,bezahle'),
    ('La maison', 'Hast du schon einmal mit Nachbarn gefeiert?', 'As-tu déjà fait la fête avec des voisins ?', 'Ja, im Mai haben wir mit den Nachbarn einen Geburtstag gefeiert.', 'Oui, en mai nous avons fêté un anniversaire avec les voisins.', 'nachbarn,gefeiert,geburtstag'),
    ('La maison', 'Wie reagierst du, wenn die Nachbarn nachts zu laut sind?', 'Comment réagis-tu quand les voisins sont trop bruyants la nuit ?', 'Dann gehe ich zu ihnen und bitte sie freundlich, leiser zu sein.', "Alors je vais les voir et je leur demande gentiment d'être plus calmes.", 'bitte,freundlich,leiser'),
    ('La maison', 'Bist du schon einmal umgezogen?', 'As-tu déjà déménagé ?', 'Ja, vor drei Jahren bin ich von Bafoussam nach Yaoundé umgezogen.', "Oui, il y a trois ans, j'ai déménagé de Bafoussam à Yaoundé.", 'umgezogen,bafoussam,yaoundé'),
    ('La maison', 'Wie war dein letzter Umzug?', "Comment s'est passé ton dernier déménagement ?", 'Er war anstrengend, aber meine Freunde haben mir mit den Kartons geholfen.', "Il était fatigant, mais mes amis m'ont aidé avec les cartons.", 'anstrengend,freunde,kartons,geholfen'),
    ('La maison', 'Wer hilft dir bei einem Umzug?', "Qui t'aide lors d'un déménagement ?", 'Bei einem Umzug helfen mir mein Bruder und zwei Freunde.', "Pour un déménagement, mon frère et deux amis m'aident.", 'umzug,helfen,bruder,freunde'),
    ('La maison', 'Möchtest du bald in eine neue Wohnung ziehen?', 'Aimerais-tu bientôt emménager dans un nouvel appartement ?', 'Ja, ich möchte im nächsten Jahr in eine größere Wohnung ziehen.', "Oui, je voudrais emménager l'année prochaine dans un appartement plus grand.", 'möchte,wohnung,größere,ziehen'),
    ('La maison', 'Wo möchtest du in zehn Jahren wohnen?', 'Où voudrais-tu habiter dans dix ans ?', 'In zehn Jahren möchte ich in einem großen Haus am Meer wohnen.', 'Dans dix ans, je voudrais habiter dans une grande maison au bord de la mer.', 'zehn,haus,meer,wohnen'),
    ('La maison', 'Wohnst du lieber in der Stadt oder auf dem Dorf?', 'Préfères-tu habiter en ville ou au village ?', 'Ich wohne lieber in der Stadt, weil es dort viele Geschäfte gibt.', "Je préfère habiter en ville, parce qu'il y a beaucoup de magasins.", 'stadt,geschäfte,lieber'),
    ('La maison', 'Was ist auf dem Dorf besser als in der Stadt?', "Qu'est-ce qui est mieux au village qu'en ville ?", 'Auf dem Dorf ist es ruhiger, und die Luft ist sauberer.', "Au village, c'est plus calme et l'air est plus propre.", 'dorf,ruhiger,luft,sauber'),
    ('La maison', 'Wo wohnen deine Großeltern?', 'Où habitent tes grands-parents ?', 'Meine Großeltern wohnen in einem Dorf im Westen von Kamerun.', "Mes grands-parents habitent dans un village à l'ouest du Cameroun.", 'großeltern,wohnen,dorf,kamerun'),
    ('La maison', 'Was gefällt dir an deinem Viertel?', "Qu'est-ce qui te plaît dans ton quartier ?", 'Mir gefällt, dass der Markt ganz in der Nähe ist.', "Ce qui me plaît, c'est que le marché est tout près.", 'gefällt,markt,nähe'),
    ('La maison', 'Wie kommst du von deinem Haus zum Markt?', 'Comment vas-tu de chez toi au marché ?', 'Ich gehe zu Fuß zum Markt, aber manchmal nehme ich ein Motorradtaxi.', 'Je vais au marché à pied, mais parfois je prends une moto-taxi.', 'fuß,markt,motorradtaxi'),
    ('La maison', 'Hast du Strom und fließendes Wasser zu Hause?', "As-tu l'électricité et l'eau courante à la maison ?", 'Ja, wir haben Strom und Wasser, aber manchmal gibt es einen Stromausfall.', "Oui, nous avons l'électricité et l'eau, mais parfois il y a une coupure de courant.", 'strom,wasser,stromausfall'),
    ('La maison', 'Was tust du bei einem Stromausfall?', 'Que fais-tu en cas de coupure de courant ?', 'Dann zünde ich eine Kerze an oder benutze die Lampe an meinem Handy.', "Alors j'allume une bougie ou j'utilise la lampe de mon téléphone.", 'kerze,lampe,handy'),
    ('La maison', 'Woher kommt das Wasser in deinem Haus?', "D'où vient l'eau dans ta maison ?", 'Das Wasser kommt aus der Leitung, aber in der Trockenzeit holen wir es am Brunnen.', "L'eau vient du robinet, mais pendant la saison sèche nous allons la chercher au puits.", 'wasser,leitung,brunnen'),
    ('La maison', 'Wie sparst du Strom und Wasser?', "Comment économises-tu l'électricité et l'eau ?", 'Ich mache das Licht aus und dusche nur fünf Minuten lang.', "J'éteins la lumière et je ne prends que cinq minutes de douche.", 'licht,dusche,minuten'),
    ('La maison', 'Duschst du morgens oder abends?', 'Prends-tu ta douche le matin ou le soir ?', 'Ich dusche lieber abends, weil ich nach der Arbeit müde bin.', 'Je préfère me doucher le soir, parce que je suis fatigué après le travail.', 'dusche,abends,müde'),
    ('La maison', 'Wie sieht dein Bad aus?', 'À quoi ressemble ta salle de bain ?', 'Mein Bad ist klein. Es gibt eine Dusche, ein Waschbecken und eine Toilette.', 'Ma salle de bain est petite. Il y a une douche, un lavabo et des toilettes.', 'bad,dusche,waschbecken,toilette'),
    ('La maison', 'Was brauchst du jeden Morgen im Bad?', 'De quoi as-tu besoin chaque matin dans la salle de bain ?', 'Ich brauche Seife, Zahnpasta und ein sauberes Handtuch.', "J'ai besoin de savon, de dentifrice et d'une serviette propre.", 'seife,zahnpasta,handtuch'),
    ('La maison', 'Hast du einen Garten?', 'As-tu un jardin ?', 'Nein, ich habe keinen Garten, aber ein paar Pflanzen im Hof.', "Non, je n'ai pas de jardin, mais quelques plantes dans la cour.", 'garten,pflanzen,hof'),
    ('La maison', 'Was wächst bei dir im Garten oder im Hof?', "Qu'est-ce qui pousse chez toi dans le jardin ou dans la cour ?", 'Bei uns wachsen Bananen, Tomaten und ein Mangobaum.', 'Chez nous poussent des bananes, des tomates et un manguier.', 'wachsen,bananen,tomaten,mangobaum'),
    ('La maison', 'Was hast du letztes Wochenende im Garten gemacht?', "Qu'as-tu fait le week-end dernier au jardin ?", 'Ich habe Unkraut gejätet und die Blumen gegossen.', "J'ai désherbé et arrosé les fleurs.", 'unkraut,blumen,gegossen'),
    ('La maison', 'Wo sitzt du abends am liebsten zu Hause?', "Où t'assieds-tu le plus volontiers le soir à la maison ?", 'Abends sitze ich am liebsten vor dem Haus und höre Musik.', "Le soir, je m'assieds le plus volontiers devant la maison et j'écoute de la musique.", 'sitze,liebsten,haus,musik'),
    ('La maison', 'Hast du einen Lieblingsplatz in deinem Haus?', 'As-tu un endroit préféré dans ta maison ?', 'Ja, mein Lieblingsplatz ist die Hängematte im Hof, dort lese ich gern.', "Oui, mon endroit préféré est le hamac dans la cour, j'y lis volontiers.", 'lieblingsplatz,hängematte,hof,lese'),
    ('La maison', 'Beschreibe dein Wohnzimmer.', 'Décris ton salon.', 'Im Wohnzimmer gibt es ein braunes Sofa, zwei Sessel und einen bunten Teppich.', 'Dans le salon, il y a un canapé marron, deux fauteuils et un tapis coloré.', 'wohnzimmer,sofa,sessel,teppich'),
    ('La maison', 'Beschreibe dein Haus von außen.', "Décris ta maison vue de l'extérieur.", 'Mein Haus ist weiß und hat ein rotes Dach und einen kleinen Zaun.', 'Ma maison est blanche et a un toit rouge et une petite clôture.', 'haus,weiß,dach,zaun'),
    ('La maison', 'Welche Möbel hast du in deinem Zimmer?', 'Quels meubles as-tu dans ta chambre ?', 'Ich habe einen Schreibtisch, einen Stuhl und ein Regal für meine Bücher.', "J'ai un bureau, une chaise et une étagère pour mes livres.", 'schreibtisch,stuhl,regal,bücher'),
    ('La maison', 'Welches Möbelstück brauchst du am dringendsten?', 'Quel meuble te faut-il le plus urgemment ?', 'Ich brauche dringend eine neue Matratze, weil meine alte sehr hart ist.', "J'ai urgemment besoin d'un nouveau matelas, parce que le mien est très dur.", 'brauche,matratze,hart'),
    ('La maison', 'Hast du schon einmal ein Möbelstück selbst gebaut?', 'As-tu déjà construit un meuble toi-même ?', 'Ja, mein Bruder und ich haben einen Tisch aus Holz gebaut.', 'Oui, mon frère et moi avons construit une table en bois.', 'tisch,holz,gebaut'),
    ('La maison', 'Wo hast du deine Möbel gekauft?', 'Où as-tu acheté tes meubles ?', 'Ich habe sie bei einem Schreiner in meinem Viertel gekauft.', 'Je les ai achetés chez un menuisier de mon quartier.', 'schreiner,viertel,gekauft'),
    ('La maison', 'Was findest du schöner: Holzmöbel oder Plastikmöbel?', 'Que trouves-tu plus joli : les meubles en bois ou en plastique ?', 'Holzmöbel finde ich schöner, aber Plastikstühle sind billiger.', 'Je trouve les meubles en bois plus jolis, mais les chaises en plastique sont moins chères.', 'holzmöbel,schöner,plastikstühle'),
    ('La maison', 'Wie dekorierst du dein Zimmer?', 'Comment décores-tu ta chambre ?', 'Ich hänge Poster und Fotos von meiner Familie an die Wand.', "J'accroche des posters et des photos de ma famille au mur.", 'poster,fotos,wand,familie'),
    ('La maison', 'Welche Farbe haben die Wände in deinem Zimmer?', 'De quelle couleur sont les murs de ta chambre ?', 'Die Wände in meinem Zimmer sind hellblau, das gefällt mir sehr.', 'Les murs de ma chambre sont bleu clair, cela me plaît beaucoup.', 'wände,hellblau,gefällt'),
    ('La maison', 'Hast du schon einmal ein Zimmer gestrichen?', 'As-tu déjà peint une chambre ?', 'Ja, vor zwei Monaten habe ich mein Zimmer grün gestrichen.', "Oui, il y a deux mois, j'ai peint ma chambre en vert.", 'zimmer,grün,gestrichen'),
    ('La maison', 'Was würdest du in deinem Haus gern ändern?', 'Que changerais-tu volontiers dans ta maison ?', 'Ich würde gern die Küche größer machen und neue Fenster einbauen.', "J'agrandirais volontiers la cuisine et je poserais de nouvelles fenêtres.", 'würde,küche,fenster'),
    ('La maison', 'Was ist das Wichtigste in einem Haus?', 'Quelle est la chose la plus importante dans une maison ?', 'Für mich ist ein sicheres Dach über dem Kopf das Wichtigste.', 'Pour moi, le plus important est un toit sûr au-dessus de la tête.', 'dach,kopf,wichtigste'),
    ('La maison', 'Seit wann wohnst du in deinem Haus?', 'Depuis quand habites-tu dans ta maison ?', 'Ich wohne seit zehn Jahren in diesem Haus.', "J'habite dans cette maison depuis dix ans.", 'wohne,seit,jahren,haus'),
    ('La maison', 'Mit wem wohnst du zusammen?', 'Avec qui habites-tu ?', 'Ich wohne mit meinen Eltern und zwei Geschwistern zusammen.', "J'habite avec mes parents et deux frères et sœurs.", 'wohne,eltern,geschwistern'),
    ('La maison', 'Wer kocht bei euch zu Hause meistens?', 'Qui cuisine le plus souvent chez vous ?', 'Bei uns kocht meistens meine Mutter, am Sonntag koche aber ich.', "Chez nous, c'est le plus souvent ma mère qui cuisine, mais le dimanche c'est moi.", 'kocht,mutter,sonntag'),
    ('La maison', 'Was gibt es heute Abend bei dir zu Hause zu essen?', "Qu'y a-t-il à manger ce soir chez toi ?", 'Heute Abend gibt es gegrillten Fisch mit Maniok.', 'Ce soir, il y a du poisson grillé avec du manioc.', 'abend,fisch,maniok'),
    ('La maison', 'Hast du eine Waschmaschine?', 'As-tu une machine à laver ?', 'Nein, ich habe keine Waschmaschine, ich wasche mit der Hand.', "Non, je n'ai pas de machine à laver, je lave à la main.", 'waschmaschine,wasche,hand'),
    ('La maison', 'Womit kochst du: mit Gas, Strom oder Holzkohle?', 'Avec quoi cuisines-tu : gaz, électricité ou charbon de bois ?', 'Ich koche mit Gas, aber meine Oma kocht noch mit Holzkohle.', 'Je cuisine au gaz, mais ma grand-mère cuisine encore au charbon de bois.', 'koche,gas,holzkohle'),
    ('La maison', 'Was ist in deinem Kühlschrank?', "Qu'y a-t-il dans ton frigo ?", 'In meinem Kühlschrank sind Wasser, Eier, Milch und etwas Obst.', "Dans mon frigo, il y a de l'eau, des œufs, du lait et un peu de fruits.", 'kühlschrank,wasser,eier,milch'),
    ('La maison', 'Wie war dein Abend gestern zu Hause?', "Comment était ta soirée d'hier à la maison ?", 'Gestern Abend habe ich mit meiner Mutter Fufu gegessen und ferngesehen.', "Hier soir, j'ai mangé du fufu avec ma mère et regardé la télévision.", 'gestern,fufu,gegessen,ferngesehen'),
    ('La maison', 'Wie verbringst du den Sonntag zu Hause?', 'Comment passes-tu le dimanche à la maison ?', 'Am Sonntag schlafe ich lange, dann putze ich mit meiner Familie das Haus.', 'Le dimanche, je dors longtemps, puis je nettoie la maison avec ma famille.', 'sonntag,schlafe,putze,haus'),
    ('La maison', 'Was machst du morgen zu Hause?', 'Que fais-tu demain à la maison ?', 'Morgen bleibe ich zu Hause und repariere die kaputte Tür.', 'Demain, je reste à la maison et je répare la porte cassée.', 'morgen,repariere,tür'),
    ('La maison', 'Das Wasser im Bad läuft nicht mehr. Was machst du?', "L'eau de la salle de bain ne coule plus. Que fais-tu ?", 'Ich rufe sofort meinen Vermieter an und bitte ihn um Hilfe.', "J'appelle tout de suite mon propriétaire et je lui demande de l'aide.", 'vermieter,rufe,hilfe'),
    ('La maison', 'Du suchst eine Wohnung. Was fragst du den Vermieter?', 'Tu cherches un logement. Que demandes-tu au propriétaire ?', 'Ich frage ihn, wie hoch die Miete ist und ob der Strom dabei ist.', "Je lui demande à combien s'élève le loyer et si l'électricité est comprise.", 'frage,miete,strom'),
    ('La maison', 'Du besuchst einen Freund. Was sagst du zu seiner Wohnung?', 'Tu rends visite à un ami. Que dis-tu de son appartement ?', 'Ich sage: Deine Wohnung ist sehr schön und gemütlich!', 'Je dis : ton appartement est très joli et agréable !', 'sage,wohnung,schön,gemütlich'),
    ('La maison', 'Ein Gast kommt zu dir. Was bietest du ihm an?', 'Un invité vient chez toi. Que lui proposes-tu ?', 'Ich biete ihm einen Stuhl und ein Glas Wasser an.', "Je lui propose une chaise et un verre d'eau.", 'biete,stuhl,wasser'),
    ('La maison', 'Wen lädst du gern zu dir nach Hause ein?', 'Qui invites-tu volontiers chez toi ?', 'Ich lade gern meine Freunde und meine Cousins zu mir ein.', "J'invite volontiers mes amis et mes cousins chez moi.", 'lade,freunde,cousins'),
    ('La maison', 'Hast du am Wochenende Besuch bekommen?', 'As-tu reçu de la visite ce week-end ?', 'Ja, meine Tante hat mich besucht, und wir haben zusammen gegessen.', "Oui, ma tante m'a rendu visite et nous avons mangé ensemble.", 'tante,besucht,gegessen'),
    ('La maison', 'Erzähl mir von einem typischen Morgen bei dir zu Hause.', "Parle-moi d'un matin typique chez toi.", 'Ich stehe um sechs Uhr auf und dusche. Dann frühstücke ich mit meiner Familie.', 'Je me lève à six heures et je me douche. Ensuite je prends le petit-déjeuner avec ma famille.', 'sechs,dusche,frühstücke'),
    ('La maison', 'Erzähl mir von deinem Traumhaus.', 'Parle-moi de la maison de tes rêves.', 'Mein Traumhaus hat einen großen Garten, einen Pool und viele Zimmer. Es steht am Meer.', 'Ma maison de rêve a un grand jardin, une piscine et beaucoup de pièces. Elle est au bord de la mer.', 'traumhaus,garten,pool,zimmer'),
    ('La maison', 'Erzähl mir von dem Haus, in dem du aufgewachsen bist.', 'Parle-moi de la maison où tu as grandi.', 'Ich bin in einem kleinen Haus im Dorf aufgewachsen. Im Hof hatten wir Hühner.', "J'ai grandi dans une petite maison au village. Dans la cour, nous avions des poules.", 'aufgewachsen,dorf,hof,hühner'),
    ('La maison', 'Was bedeutet Zuhause für dich?', 'Que signifie « chez soi » pour toi ?', 'Zuhause bedeutet für mich Ruhe, Familie und gutes Essen.', 'Pour moi, chez soi signifie le calme, la famille et la bonne cuisine.', 'zuhause,ruhe,familie,essen'),
    ('La maison', 'Wo arbeitest du zu Hause am liebsten?', 'Où travailles-tu le plus volontiers à la maison ?', 'Ich arbeite am liebsten am Tisch im Wohnzimmer, dort ist es hell.', 'Je travaille le plus volontiers à la table du salon, il y fait clair.', 'arbeite,tisch,wohnzimmer,hell'),
    ('La maison', 'Welche Geräte hast du zu Hause?', 'Quels appareils as-tu à la maison ?', 'Zu Hause habe ich einen Fernseher, ein Radio und einen Computer.', "À la maison, j'ai une télévision, une radio et un ordinateur.", 'fernseher,radio,computer'),
    ('La maison', 'Wie bleibt dein Haus an heißen Tagen kühl?', 'Comment ta maison reste-t-elle fraîche les jours de forte chaleur ?', 'An heißen Tagen öffne ich die Fenster und schalte den Ventilator ein.', "Les jours de chaleur, j'ouvre les fenêtres et j'allume le ventilateur.", 'heißen,fenster,ventilator'),
    ('La maison', 'Wie verbringst du die Regenzeit zu Hause?', 'Comment passes-tu la saison des pluies à la maison ?', 'In der Regenzeit bleibe ich zu Hause, höre den Regen und spiele mit meinen Geschwistern Karten.', "Pendant la saison des pluies, je reste à la maison, j'écoute la pluie et je joue aux cartes avec mes frères et sœurs.", 'regenzeit,regen,karten'),
    ('La maison', 'Tropft das Dach bei dir in der Regenzeit?', 'Est-ce que le toit goutte chez toi pendant la saison des pluies ?', 'Ja, bei starkem Regen kommt Wasser durch das Dach.', "Oui, quand il pleut fort, de l'eau passe à travers le toit.", 'regen,wasser,dach'),
    ('La maison', 'Schließt du abends die Tür ab?', 'Fermes-tu la porte à clé le soir ?', 'Ja, abends schließe ich immer die Tür ab und mache das Licht aus.', "Oui, le soir je ferme toujours la porte à clé et j'éteins la lumière.", 'schließe,tür,licht'),
    ('La maison', 'Wann bist du gestern nach Hause gekommen?', 'À quelle heure es-tu rentré hier à la maison ?', 'Ich bin gestern um sieben Uhr abends nach Hause gekommen.', 'Je suis rentré hier à sept heures du soir.', 'gestern,sieben,gekommen'),
    ('La maison', 'Welchen Gegenstand hast du zuletzt für dein Zuhause gekauft?', 'Quel objet as-tu acheté en dernier pour ta maison ?', 'Ich habe einen großen Spiegel für das Schlafzimmer gekauft.', "J'ai acheté un grand miroir pour la chambre.", 'spiegel,schlafzimmer,gekauft'),
    ('La maison', 'Hast du heute schon das Geschirr gespült?', "As-tu déjà fait la vaisselle aujourd'hui ?", 'Ja, nach dem Mittagessen habe ich das ganze Geschirr gespült.', "Oui, après le déjeuner j'ai fait toute la vaisselle.", 'geschirr,gespült,mittagessen'),
    ('La maison', 'Wie oft wechselst du deine Bettwäsche?', 'À quelle fréquence changes-tu tes draps ?', 'Ich wechsle meine Bettwäsche alle zwei Wochen.', 'Je change mes draps toutes les deux semaines.', 'bettwäsche,wechsle,wochen'),
    ('La maison', 'Was riecht in deinem Haus am besten?', "Qu'est-ce qui sent le meilleur dans ta maison ?", 'In meinem Haus riecht es am besten, wenn meine Mutter Ndolé kocht.', 'Dans ma maison, cela sent le meilleur quand ma mère cuisine du ndolé.', 'riecht,mutter,ndolé'),
    ('La maison', 'Teilst du dein Zimmer mit jemandem?', "Partages-tu ta chambre avec quelqu'un ?", 'Ja, ich teile mein Zimmer mit meinem kleinen Bruder.', 'Oui, je partage ma chambre avec mon petit frère.', 'teile,zimmer,bruder'),
    ('La maison', 'Wie findest du alte Lehmhäuser im Dorf?', 'Que penses-tu des vieilles maisons en terre au village ?', 'Ich finde Lehmhäuser schön, denn sie sind drinnen angenehm kühl.', "Je trouve les maisons en terre jolies, car elles sont agréablement fraîches à l'intérieur.", 'lehmhäuser,schön,kühl'),
    ('La maison', 'Würdest du lieber allein oder mit Freunden wohnen?', 'Préférerais-tu habiter seul ou avec des amis ?', 'Ich würde lieber mit Freunden wohnen, denn allein ist es oft einsam.', 'Je préférerais habiter avec des amis, car seul, on se sent souvent isolé.', 'würde,freunden,allein'),
    ('La maison', 'Wer bringt bei euch den Müll raus?', 'Qui sort les poubelles chez vous ?', 'Bei uns bringt mein Bruder jeden Abend den Müll raus.', "Chez nous, c'est mon frère qui sort les poubelles chaque soir.", 'müll,bruder,abend'),
    ('La maison', 'Was würdest du jemandem raten, der eine Wohnung sucht?', "Que conseillerais-tu à quelqu'un qui cherche un logement ?", 'Ich würde zuerst das Viertel anschauen und die Nachbarn fragen.', "Je regarderais d'abord le quartier et je demanderais aux voisins.", 'würde,viertel,nachbarn'),
    ('La maison', 'Wie hast du dein Zimmer eingerichtet?', 'Comment as-tu aménagé ta chambre ?', 'Ich habe das Bett an die Wand gestellt und den Tisch ans Fenster.', "J'ai mis le lit contre le mur et la table près de la fenêtre.", 'bett,wand,tisch,fenster'),
    ('La maison', 'Wie hast du deine Wohnung gefunden?', 'Comment as-tu trouvé ton logement ?', 'Ich habe sie über einen Freund gefunden, er kannte den Vermieter.', "Je l'ai trouvé grâce à un ami, il connaissait le propriétaire.", 'gefunden,freund,vermieter'),
    ('La maison', 'Was hast du gestern gekocht?', "Qu'as-tu cuisiné hier ?", 'Gestern habe ich Reis mit Tomatensoße und Hähnchen gekocht.', "Hier, j'ai cuisiné du riz avec de la sauce tomate et du poulet.", 'gestern,reis,hähnchen,gekocht'),
    ('La maison', 'Wo hast du als Kind gewohnt?', 'Où habitais-tu quand tu étais enfant ?', 'Als Kind habe ich in Douala gewohnt, in einem großen Viertel.', "Quand j'étais enfant, j'habitais à Douala, dans un grand quartier.", 'kind,douala,gewohnt'),
    ('La maison', 'Welche Reparatur hast du zuletzt im Haus gemacht?', 'Quelle réparation as-tu faite en dernier dans la maison ?', 'Ich habe den Wasserhahn in der Küche repariert.', "J'ai réparé le robinet de la cuisine.", 'wasserhahn,küche,repariert'),
    ('La maison', 'Wann hast du zuletzt die Fenster geputzt?', 'Quand as-tu nettoyé les fenêtres pour la dernière fois ?', 'Ich habe die Fenster vor einem Monat geputzt, jetzt sind sie schon wieder schmutzig.', "J'ai nettoyé les fenêtres il y a un mois, maintenant elles sont déjà de nouveau sales.", 'fenster,geputzt,schmutzig'),
    ('La maison', 'Willst du dein Haus bald renovieren?', 'Veux-tu bientôt rénover ta maison ?', 'Nein, aber nächstes Jahr möchte ich das Dach reparieren lassen.', "Non, mais l'année prochaine je voudrais faire réparer le toit.", 'nächstes,dach,reparieren'),
    ('La maison', 'Was möchtest du für deine erste eigene Wohnung kaufen?', 'Que voudrais-tu acheter pour ton premier appartement à toi ?', 'Für meine erste Wohnung möchte ich zuerst ein Bett und einen Kühlschrank kaufen.', "Pour mon premier appartement, je voudrais d'abord acheter un lit et un frigo.", 'wohnung,bett,kühlschrank'),
    ('La maison', 'Welche Arbeiten planst du dieses Wochenende im Haus?', 'Quels travaux prévois-tu cette fin de semaine dans la maison ?', 'Dieses Wochenende streiche ich die Tür und räume den Hof auf.', 'Ce week-end, je peins la porte et je range la cour.', 'wochenende,streiche,hof'),
    ('La maison', 'Wann ziehst du von deinen Eltern aus?', 'Quand quitteras-tu la maison de tes parents ?', 'Ich ziehe vielleicht in zwei Jahren aus, wenn ich eine Arbeit habe.', "Je déménagerai peut-être dans deux ans, quand j'aurai un travail.", 'ziehe,jahren,arbeit'),
    ('Le travail', 'Was bist du von Beruf?', 'Quel est ton métier ?', 'Ich bin Informatiker und arbeite mit Computern.', 'Je suis informaticien et je travaille avec des ordinateurs.', 'informatiker,arbeite,computer'),
    ('Le travail', 'Arbeitest du gern?', 'Aimes-tu travailler ?', 'Ja, ich arbeite sehr gern, denn meine Arbeit macht mir Spaß.', "Oui, j'aime beaucoup travailler, car mon travail me plaît.", 'arbeite,gern,spaß'),
    ('Le travail', 'Wo arbeitest du?', 'Où travailles-tu ?', 'Ich arbeite in einem kleinen Büro in Yaoundé.', 'Je travaille dans un petit bureau à Yaoundé.', 'arbeite,büro,yaoundé'),
    ('Le travail', 'Wie heißt dein Chef?', "Comment s'appelle ton chef ?", 'Mein Chef heißt Herr Mbarga. Er ist sehr nett.', "Mon chef s'appelle monsieur Mbarga. Il est très gentil.", 'chef,heißt,nett'),
    ('Le travail', 'Wie sind deine Kollegen?', 'Comment sont tes collègues ?', 'Meine Kollegen sind freundlich und hilfsbereit.', 'Mes collègues sont aimables et serviables.', 'kollegen,freundlich,hilfsbereit'),
    ('Le travail', 'Wann beginnt deine Arbeit am Morgen?', 'À quelle heure commence ton travail le matin ?', 'Meine Arbeit beginnt um acht Uhr.', 'Mon travail commence à huit heures.', 'beginnt,arbeit,uhr'),
    ('Le travail', 'Wann hast du Feierabend?', 'À quelle heure finis-tu ta journée de travail ?', 'Um fünf Uhr habe ich Feierabend und fahre nach Hause.', 'À cinq heures, ma journée est finie et je rentre à la maison.', 'feierabend,uhr,fünf'),
    ('Le travail', 'Wie viele Stunden arbeitest du pro Tag?', "Combien d'heures travailles-tu par jour ?", 'Ich arbeite acht Stunden pro Tag.', 'Je travaille huit heures par jour.', 'stunden,arbeite,acht'),
    ('Le travail', 'Hast du ein Büro?', 'As-tu un bureau ?', 'Ja, ich habe ein kleines Büro mit einem Schreibtisch und einem Computer.', "Oui, j'ai un petit bureau avec une table de travail et un ordinateur.", 'büro,schreibtisch,computer'),
    ('Le travail', 'Was steht auf deinem Schreibtisch?', "Qu'y a-t-il sur ton bureau (table de travail) ?", 'Auf meinem Schreibtisch steht ein Computer. Daneben liegen Stifte und Papier.', 'Sur mon bureau, il y a un ordinateur. À côté, il y a des stylos et du papier.', 'schreibtisch,computer,papier'),
    ('Le travail', 'Arbeitest du am Wochenende?', 'Travailles-tu le week-end ?', 'Nein, am Wochenende arbeite ich nicht. Da habe ich frei.', 'Non, le week-end, je ne travaille pas. Là, je suis libre.', 'wochenende,arbeite,frei'),
    ('Le travail', 'Wie kommst du zur Arbeit?', 'Comment vas-tu au travail ?', 'Ich gehe zu Fuß zur Arbeit, denn mein Büro ist nicht weit.', "Je vais au travail à pied, car mon bureau n'est pas loin.", 'fuß,gehe,arbeit'),
    ('Le travail', 'Wie lange brauchst du bis zur Arbeit?', 'Combien de temps te faut-il pour aller au travail ?', 'Ich brauche zwanzig Minuten mit dem Bus.', 'Il me faut vingt minutes en bus.', 'brauche,minuten,bus'),
    ('Le travail', 'Was machst du in der Mittagspause?', 'Que fais-tu pendant la pause de midi ?', 'In der Mittagspause esse ich etwas und telefoniere mit meiner Familie.', "À la pause de midi, je mange quelque chose et j'appelle ma famille.", 'mittagspause,esse,telefoniere'),
    ('Le travail', 'Wie viel Wasser hast du heute bei der Arbeit getrunken?', "Combien d'eau as-tu bu aujourd'hui au travail ?", 'Heute habe ich schon zwei Flaschen Wasser getrunken.', "Aujourd'hui, j'ai déjà bu deux bouteilles d'eau.", 'wasser,getrunken,flaschen'),
    ('Le travail', 'Hast du heute viel zu tun?', "As-tu beaucoup à faire aujourd'hui ?", 'Ja, heute habe ich viel zu tun. Ich habe drei Termine.', "Oui, aujourd'hui j'ai beaucoup à faire. J'ai trois rendez-vous.", 'viel,tun,termine'),
    ('Le travail', 'Was ist dein Traumberuf?', 'Quel est le métier de tes rêves ?', 'Mein Traumberuf ist Lehrer. Ich möchte Kindern etwas beibringen.', "Le métier de mes rêves, c'est enseignant. Je veux apprendre des choses aux enfants.", 'traumberuf,lehrer,möchte'),
    ('Le travail', 'Was wolltest du als Kind werden?', 'Que voulais-tu devenir quand tu étais enfant ?', 'Als Kind wollte ich Pilot werden, weil ich Flugzeuge toll fand.', 'Enfant, je voulais devenir pilote parce que je trouvais les avions formidables.', 'kind,wollte,pilot,flugzeuge'),
    ('Le travail', 'Arbeitest du lieber drinnen oder draußen?', "Préfères-tu travailler à l'intérieur ou dehors ?", 'Ich arbeite lieber draußen, denn ich bin gern an der frischen Luft.', "Je préfère travailler dehors, car j'aime être au grand air.", 'lieber,draußen,arbeite'),
    ('Le travail', 'Arbeitest du lieber allein oder im Team?', 'Préfères-tu travailler seul ou en équipe ?', 'Ich arbeite lieber im Team, weil wir dann mehr Ideen haben.', "Je préfère travailler en équipe parce qu'on a alors plus d'idées.", 'team,lieber,ideen'),
    ('Le travail', 'Was brauchst du für deine Arbeit?', 'De quoi as-tu besoin pour ton travail ?', 'Für meine Arbeit brauche ich einen Laptop und Internet.', "Pour mon travail, j'ai besoin d'un ordinateur portable et d'Internet.", 'brauche,laptop,internet'),
    ('Le travail', 'Wie viele Kollegen hast du?', 'Combien de collègues as-tu ?', 'Ich habe sieben Kollegen. Wir sind ein kleines Team.', "J'ai sept collègues. Nous sommes une petite équipe.", 'kollegen,sieben,team'),
    ('Le travail', 'Wann hast du Urlaub?', 'Quand as-tu des congés ?', 'Im August habe ich zwei Wochen Urlaub.', "En août, j'ai deux semaines de congé.", 'urlaub,august,wochen'),
    ('Le travail', 'Welchen Wochentag magst du bei der Arbeit am liebsten?', 'Quel jour de la semaine préfères-tu au travail ?', 'Ich mag den Freitag am liebsten, weil danach das Wochenende kommt.', "Je préfère le vendredi, parce qu'ensuite vient le week-end.", 'freitag,wochenende,liebsten'),
    ('Le travail', 'Telefonierst du viel bei der Arbeit?', 'Téléphones-tu beaucoup au travail ?', 'Ja, ich telefoniere jeden Tag mit Kunden.', 'Oui, je téléphone tous les jours à des clients.', 'telefoniere,kunden,jeden'),
    ('Le travail', 'Schreibst du bei der Arbeit viele E-Mails?', "Écris-tu beaucoup d'e-mails au travail ?", 'Ja, jeden Morgen schreibe ich einige E-Mails.', "Oui, chaque matin j'écris quelques e-mails.", 'e-mails,schreibe,morgen'),
    ('Le travail', 'Wie heißt deine Firma?', "Comment s'appelle ton entreprise ?", 'Meine Firma heißt Kamer Tech. Sie ist ziemlich klein.', "Mon entreprise s'appelle Kamer Tech. Elle est assez petite.", 'firma,heißt,klein'),
    ('Le travail', 'Was verkauft deine Firma?', 'Que vend ton entreprise ?', 'Unsere Firma verkauft Handys und Zubehör.', 'Notre entreprise vend des téléphones portables et des accessoires.', 'firma,verkauft,handys'),
    ('Le travail', 'Was ist das Erste, was du im Büro machst?', 'Quelle est la première chose que tu fais au bureau ?', 'Zuerst schalte ich den Computer ein und lese meine E-Mails.', "D'abord, j'allume l'ordinateur et je lis mes e-mails.", 'zuerst,computer,schalte'),
    ('Le travail', 'Wofür gibst du dein Gehalt am meisten aus?', 'Pour quoi dépenses-tu le plus ton salaire ?', 'Ich gebe mein Gehalt meistens für Miete und Essen aus.', 'Je dépense surtout mon salaire pour le loyer et la nourriture.', 'gehalt,miete,essen'),
    ('Le travail', 'Wie bekommst du dein Gehalt: bar oder per Mobile Money?', 'Comment reçois-tu ton salaire : en espèces ou par Mobile Money ?', 'Ich bekomme mein Gehalt per Mobile Money auf mein Handy.', 'Je reçois mon salaire par Mobile Money sur mon téléphone.', 'gehalt,mobile,handy'),
    ('Le travail', 'Welche Sprachen sprichst du bei der Arbeit?', 'Quelles langues parles-tu au travail ?', 'Bei der Arbeit spreche ich Französisch und ein bisschen Englisch.', 'Au travail, je parle français et un peu anglais.', 'spreche,französisch,englisch'),
    ('Le travail', 'Mit welchem Kollegen verstehst du dich am besten?', "Avec quel collègue t'entends-tu le mieux ?", 'Ich verstehe mich am besten mit Paul, denn wir lachen oft zusammen.', "Je m'entends le mieux avec Paul, car nous rions souvent ensemble.", 'verstehe,lachen,zusammen'),
    ('Le travail', 'Ist dein Chef streng?', 'Ton chef est-il sévère ?', 'Nein, mein Chef ist nicht streng. Er ist ruhig und fair.', "Non, mon chef n'est pas sévère. Il est calme et juste.", 'chef,streng,fair'),
    ('Le travail', 'Was gefällt dir an deinem Chef?', "Qu'est-ce qui te plaît chez ton chef ?", 'Mir gefällt, dass mein Chef immer ehrlich ist.', "Ce qui me plaît, c'est que mon chef est toujours honnête.", 'chef,gefällt,ehrlich'),
    ('Le travail', 'Welche Farbe hat dein Computer?', 'De quelle couleur est ton ordinateur ?', 'Mein Computer ist schwarz. Ich habe ihn seit zwei Jahren.', "Mon ordinateur est noir. Je l'ai depuis deux ans.", 'computer,schwarz,jahren'),
    ('Le travail', 'Wie oft hast du gestern Pause gemacht?', 'Combien de fois as-tu fait une pause hier ?', 'Gestern habe ich zweimal Pause gemacht.', "Hier, j'ai fait deux fois une pause.", 'gestern,pause,zweimal'),
    ('Le travail', 'Wo hast du gestern Mittag gegessen?', 'Où as-tu mangé hier à midi ?', 'Gestern habe ich in der Kantine gegessen. Dort gab es Reis mit Fisch.', "Hier, j'ai mangé à la cantine. Il y avait du riz avec du poisson.", 'gestern,kantine,gegessen,reis'),
    ('Le travail', 'Was bringst du zur Arbeit mit?', "Qu'apportes-tu avec toi au travail ?", 'Ich bringe Wasser, einen Apfel und mein Handy mit.', "J'apporte de l'eau, une pomme et mon téléphone.", 'bringe,wasser,apfel,handy'),
    ('Le travail', 'Um wie viel Uhr bist du heute zur Arbeit losgefahren?', "À quelle heure es-tu parti pour le travail aujourd'hui ?", 'Ich bin heute schon um sieben Uhr losgefahren.', "Je suis déjà parti à sept heures aujourd'hui.", 'losgefahren,uhr,sieben'),
    ('Le travail', 'Was hast du gestern bei der Arbeit gemacht?', "Qu'as-tu fait hier au travail ?", 'Gestern habe ich viele E-Mails geschrieben und zwei Kunden angerufen.', "Hier, j'ai écrit beaucoup d'e-mails et appelé deux clients.", 'gestern,geschrieben,angerufen,kunden'),
    ('Le travail', 'Seit wann arbeitest du in deiner Firma?', 'Depuis quand travailles-tu dans ton entreprise ?', 'Ich arbeite seit drei Jahren in meiner Firma.', 'Je travaille dans mon entreprise depuis trois ans.', 'seit,jahren,arbeite'),
    ('Le travail', 'Wie war dein erster Arbeitstag?', 'Comment était ton premier jour de travail ?', 'Mein erster Arbeitstag war aufregend. Ich war nervös, aber alle waren nett.', "Mon premier jour de travail était passionnant. J'étais nerveux, mais tout le monde était gentil.", 'arbeitstag,aufregend,nervös'),
    ('Le travail', 'Hast du schon einmal ein Praktikum gemacht?', 'As-tu déjà fait un stage ?', 'Ja, ich habe letztes Jahr ein Praktikum in einer Bank gemacht.', "Oui, j'ai fait un stage dans une banque l'année dernière.", 'praktikum,gemacht,bank'),
    ('Le travail', 'Wo möchtest du gern ein Praktikum machen?', 'Où aimerais-tu faire un stage ?', 'Ich möchte gern ein Praktikum in einem Krankenhaus machen.', "J'aimerais faire un stage dans un hôpital.", 'praktikum,möchte,krankenhaus'),
    ('Le travail', 'Was hast du in deinem Praktikum gelernt?', "Qu'as-tu appris pendant ton stage ?", 'Im Praktikum habe ich gelernt, pünktlich zu sein und im Team zu arbeiten.', "Pendant le stage, j'ai appris à être ponctuel et à travailler en équipe.", 'praktikum,gelernt,pünktlich,team'),
    ('Le travail', 'Hast du schon eine Bewerbung geschrieben?', 'As-tu déjà écrit une candidature ?', 'Ja, letzte Woche habe ich eine Bewerbung geschrieben.', "Oui, la semaine dernière, j'ai écrit une candidature.", 'bewerbung,geschrieben,woche'),
    ('Le travail', 'Was schreibst du in deinen Lebenslauf?', "Qu'écris-tu dans ton CV ?", 'In meinen Lebenslauf schreibe ich meinen Namen, meine Schule und meine Praktika.', "Dans mon CV, j'écris mon nom, mon école et mes stages.", 'lebenslauf,schule,praktika'),
    ('Le travail', 'Du hast morgen ein Vorstellungsgespräch. Wie bereitest du dich vor?', "Demain, tu as un entretien d'embauche. Comment te prépares-tu ?", 'Ich übe zu Hause die Fragen und komme zehn Minuten früher.', "Je m'entraîne à la maison avec les questions et j'arrive dix minutes plus tôt.", 'übe,fragen,früher'),
    ('Le travail', 'Warum arbeitest du?', 'Pourquoi travailles-tu ?', 'Ich arbeite, weil ich Geld verdienen möchte.', "Je travaille parce que je veux gagner de l'argent.", 'arbeite,geld,verdienen'),
    ('Le travail', 'Warum gefällt dir deine Arbeit?', 'Pourquoi ton travail te plaît-il ?', 'Meine Arbeit gefällt mir, weil ich viele Menschen treffe.', 'Mon travail me plaît parce que je rencontre beaucoup de gens.', 'gefällt,menschen,treffe'),
    ('Le travail', 'Was gefällt dir an deiner Arbeit nicht?', "Qu'est-ce qui ne te plaît pas dans ton travail ?", 'Mir gefällt nicht, dass ich oft lange sitzen muss.', "Ce qui ne me plaît pas, c'est que je dois souvent rester assis longtemps.", 'gefällt,nicht,sitzen'),
    ('Le travail', 'Wie findest du deine Arbeitszeiten?', 'Comment trouves-tu tes horaires de travail ?', 'Ich finde meine Arbeitszeiten gut, denn ich habe am Nachmittag Zeit für die Familie.', "Je trouve mes horaires bons, car j'ai du temps pour la famille l'après-midi.", 'arbeitszeiten,finde,gut,familie'),
    ('Le travail', 'Was findest du bei der Arbeit am wichtigsten?', "Qu'est-ce qui est le plus important pour toi au travail ?", 'Am wichtigsten finde ich ein faires Gehalt und nette Kollegen.', "Le plus important pour moi, c'est un salaire correct et des collègues sympathiques.", 'wichtigsten,gehalt,kollegen'),
    ('Le travail', 'Ist Stress bei der Arbeit ein Problem für dich?', 'Le stress au travail est-il un problème pour toi ?', 'Ja, manchmal habe ich Stress, besonders am Montag.', "Oui, parfois j'ai du stress, surtout le lundi.", 'stress,manchmal,montag'),
    ('Le travail', 'Was machst du, wenn du Stress hast?', 'Que fais-tu quand tu es stressé ?', 'Wenn ich Stress habe, höre ich Musik und gehe spazieren.', "Quand je suis stressé, j'écoute de la musique et je vais me promener.", 'stress,musik,spazieren'),
    ('Le travail', 'Wie entspannst du dich nach der Arbeit?', 'Comment te détends-tu après le travail ?', 'Nach der Arbeit sehe ich fern oder spiele mit Freunden Fußball.', 'Après le travail, je regarde la télé ou je joue au football avec des amis.', 'arbeit,fern,fußball'),
    ('Le travail', 'Bist du nach der Arbeit oft müde?', 'Es-tu souvent fatigué après le travail ?', 'Ja, am Abend bin ich oft sehr müde.', 'Oui, le soir, je suis souvent très fatigué.', 'müde,abend,oft'),
    ('Le travail', 'Wo hast du vorher gearbeitet?', 'Où as-tu travaillé auparavant ?', 'Vorher habe ich in einem Hotel in Douala gearbeitet.', "Avant, j'ai travaillé dans un hôtel à Douala.", 'vorher,hotel,gearbeitet,douala'),
    ('Le travail', 'Wie hast du deine erste Arbeit gefunden?', 'Comment as-tu trouvé ton premier travail ?', 'Ein Freund hat mir von der Stelle erzählt, und dann habe ich mich beworben.', "Un ami m'a parlé du poste, et ensuite j'ai postulé.", 'freund,stelle,beworben'),
    ('Le travail', 'Wann ist dein nächstes Meeting?', 'Quand est ta prochaine réunion ?', 'Mein nächstes Meeting ist am Mittwoch um zehn Uhr.', 'Ma prochaine réunion est mercredi à dix heures.', 'meeting,mittwoch,uhr'),
    ('Le travail', 'Worüber sprecht ihr im Meeting?', 'De quoi parlez-vous en réunion ?', 'Im Meeting sprechen wir über neue Kunden und die Pläne für die Woche.', 'En réunion, nous parlons de nouveaux clients et des projets de la semaine.', 'meeting,kunden,pläne'),
    ('Le travail', 'Wie findest du Meetings bei der Arbeit?', 'Comment trouves-tu les réunions au travail ?', 'Ich finde Meetings manchmal zu lang, aber sie sind wichtig.', 'Je trouve les réunions parfois trop longues, mais elles sont importantes.', 'meetings,lang,wichtig'),
    ('Le travail', 'Was ist für dich ein guter Chef?', "Pour toi, qu'est-ce qu'un bon chef ?", 'Für mich ist ein guter Chef geduldig und hört gut zu.', 'Pour moi, un bon chef est patient et sait bien écouter.', 'chef,geduldig,hört'),
    ('Le travail', 'Möchtest du lieber Angestellter oder Chef sein?', 'Préfères-tu être employé ou chef ?', 'Ich möchte lieber Chef sein, weil ich dann selbst entscheiden kann.', 'Je préfère être chef, parce que je peux alors décider moi-même.', 'lieber,chef,entscheiden'),
    ('Le travail', 'Hast du schon einmal etwas auf dem Markt verkauft?', 'As-tu déjà vendu quelque chose au marché ?', 'Ja, ich habe auf dem Markt in Yaoundé Tomaten verkauft.', "Oui, j'ai vendu des tomates au marché à Yaoundé.", 'markt,verkauft,tomaten'),
    ('Le travail', 'Welches Geschäft würdest du in deiner Stadt eröffnen?', 'Quel commerce ouvrirais-tu dans ta ville ?', 'Ich würde eine Bäckerei eröffnen, denn alle essen gern frisches Brot.', "J'ouvrirais une boulangerie, car tout le monde aime manger du pain frais.", 'würde,bäckerei,eröffnen'),
    ('Le travail', 'Wie viele Tage pro Woche arbeitest du?', 'Combien de jours par semaine travailles-tu ?', 'Ich arbeite fünf Tage pro Woche, von Montag bis Freitag.', 'Je travaille cinq jours par semaine, du lundi au vendredi.', 'tage,woche,montag,freitag'),
    ('Le travail', 'Machst du manchmal Überstunden?', 'Fais-tu parfois des heures supplémentaires ?', 'Ja, am Monatsende mache ich oft Überstunden.', 'Oui, en fin de mois, je fais souvent des heures supplémentaires.', 'überstunden,monatsende,mache'),
    ('Le travail', 'Arbeitest du auch von zu Hause?', 'Travailles-tu aussi depuis chez toi ?', 'Ja, am Dienstag arbeite ich zu Hause am Laptop.', 'Oui, le mardi, je travaille à la maison sur mon ordinateur portable.', 'hause,laptop,dienstag'),
    ('Le travail', 'Was ist beim Arbeiten zu Hause schwierig für dich?', "Qu'est-ce qui est difficile pour toi quand tu travailles à la maison ?", 'Zu Hause ist es oft laut, deshalb kann ich mich schlecht konzentrieren.', "À la maison, il y a souvent du bruit, donc j'ai du mal à me concentrer.", 'hause,laut,konzentrieren'),
    ('Le travail', 'Wo arbeitest du lieber: im Büro oder zu Hause?', 'Où préfères-tu travailler : au bureau ou à la maison ?', 'Ich arbeite lieber im Büro, weil ich dort meine Kollegen sehe.', "Je préfère travailler au bureau, parce que j'y vois mes collègues.", 'lieber,büro,kollegen'),
    ('Le travail', 'Was machst du morgen bei der Arbeit?', 'Que fais-tu demain au travail ?', 'Morgen schreibe ich einen Bericht und rufe einen Kunden an.', "Demain, j'écris un rapport et j'appelle un client.", 'morgen,bericht,kunden'),
    ('Le travail', 'Was möchtest du in fünf Jahren beruflich erreichen?', 'Que voudrais-tu atteindre professionnellement dans cinq ans ?', 'In fünf Jahren möchte ich eine gute Stelle in einer großen Firma haben.', 'Dans cinq ans, je voudrais avoir un bon poste dans une grande entreprise.', 'jahren,stelle,firma'),
    ('Le travail', 'Welche Pläne hast du für deine Karriere?', 'Quels projets as-tu pour ta carrière ?', 'Ich will zuerst Erfahrung sammeln und dann eine Weiterbildung machen.', "Je veux d'abord acquérir de l'expérience, puis suivre une formation continue.", 'erfahrung,weiterbildung,sammeln'),
    ('Le travail', 'Suchst du im Moment eine neue Arbeit?', 'Cherches-tu un nouveau travail en ce moment ?', 'Nein, im Moment suche ich keine neue Arbeit. Ich bin zufrieden.', 'Non, en ce moment je ne cherche pas de nouveau travail. Je suis satisfait.', 'suche,arbeit,zufrieden'),
    ('Le travail', 'Wo suchst du Stellenanzeigen?', "Où cherches-tu des offres d'emploi ?", 'Ich suche Stellenanzeigen im Internet und auf Facebook.', "Je cherche des offres d'emploi sur Internet et sur Facebook.", 'stellenanzeigen,internet,suche'),
    ('Le travail', 'Was hast du heute Morgen vor der Arbeit gegessen?', "Qu'as-tu mangé ce matin avant le travail ?", 'Heute Morgen habe ich Brot mit Ei gegessen und Tee getrunken.', "Ce matin, j'ai mangé du pain avec un œuf et bu du thé.", 'morgen,gegessen,getrunken'),
    ('Le travail', 'Was war gestern bei der Arbeit besonders schön?', "Qu'y a-t-il eu de particulièrement agréable hier au travail ?", 'Gestern hat mein Chef mich gelobt. Das war sehr schön.', "Hier, mon chef m'a félicité. C'était très agréable.", 'gestern,chef,gelobt'),
    ('Le travail', 'Bist du heute zu spät zur Arbeit gekommen?', "Es-tu arrivé en retard au travail aujourd'hui ?", 'Nein, ich bin heute pünktlich gekommen. Es gab keinen Stau.', "Non, je suis arrivé à l'heure aujourd'hui. Il n'y avait pas d'embouteillage.", 'pünktlich,gekommen,stau'),
    ('Le travail', 'Erzähl mir von einem typischen Arbeitstag bei dir.', 'Raconte-moi une journée de travail typique chez toi.', 'Ich stehe früh auf und beginne um acht Uhr mit der Arbeit. Nach dem Mittagessen habe ich Termine, und um fünf fahre ich nach Hause.', "Je me lève tôt et je commence le travail à huit heures. Après le déjeuner, j'ai des rendez-vous, et à cinq heures je rentre à la maison.", 'früh,termine,mittagessen'),
    ('Le travail', 'Beschreibe deinen idealen Arbeitsplatz.', 'Décris ton lieu de travail idéal.', 'Mein idealer Arbeitsplatz ist hell und ruhig. Er hat ein großes Fenster und eine Kaffeemaschine.', 'Mon lieu de travail idéal est lumineux et calme. Il a une grande fenêtre et une machine à café.', 'arbeitsplatz,hell,ruhig,fenster'),
    ('Le travail', 'Du bist neu in der Firma. Wie stellst du dich vor?', "Tu es nouveau dans l'entreprise. Comment te présentes-tu ?", 'Guten Morgen, ich heiße Samuel und arbeite ab heute hier. Ich freue mich auf die Zusammenarbeit.', "Bonjour, je m'appelle Samuel et je travaille ici à partir d'aujourd'hui. Je me réjouis de cette collaboration.", 'heiße,arbeite,freue'),
    ('Le travail', 'Dein Computer funktioniert nicht. Was sagst du deinem Kollegen?', 'Ton ordinateur ne fonctionne pas. Que dis-tu à ton collègue ?', 'Entschuldigung, mein Computer funktioniert nicht. Kannst du mir bitte helfen?', "Excuse-moi, mon ordinateur ne fonctionne pas. Peux-tu m'aider, s'il te plaît ?", 'computer,helfen,kannst'),
    ('Le travail', 'Du kommst zu spät zur Arbeit. Was sagst du deinem Chef?', 'Tu arrives en retard au travail. Que dis-tu à ton chef ?', 'Es tut mir leid, dass ich zu spät bin. Auf der Straße war viel Verkehr.', "Je suis désolé d'être en retard. Il y avait beaucoup de circulation dans la rue.", 'leid,spät,verkehr'),
    ('Le travail', 'Du brauchst einen Tag frei. Wie fragst du deinen Chef?', "Tu as besoin d'un jour de congé. Comment le demandes-tu à ton chef ?", 'Könnte ich am Freitag bitte einen Tag frei bekommen? Ich habe einen Arzttermin.', "Pourrais-je avoir un jour de congé vendredi, s'il vous plaît ? J'ai un rendez-vous chez le médecin.", 'frei,freitag,arzttermin'),
    ('Le travail', 'Ein Kunde ruft an. Wie meldest du dich am Telefon?', 'Un client appelle. Comment réponds-tu au téléphone ?', 'Guten Tag, hier spricht Samuel von Kamer Tech. Wie kann ich Ihnen helfen?', 'Bonjour, ici Samuel de Kamer Tech. Comment puis-je vous aider ?', 'guten,spricht,helfen'),
    ('Le travail', 'Du hast einen Stand auf dem Markt in Douala. Was verkaufst du?', 'Tu as un étal au marché de Douala. Que vends-tu ?', 'Ich verkaufe frisches Gemüse, Bananen und Reis.', 'Je vends des légumes frais, des bananes et du riz.', 'verkaufe,gemüse,bananen'),
    ('Le travail', 'Nimmst du ein Taxi-Moto, wenn du spät dran bist?', 'Prends-tu un taxi-moto quand tu es en retard ?', 'Ja, wenn ich spät dran bin, nehme ich ein Taxi-Moto. Es ist schneller als der Bus.', "Oui, quand je suis en retard, je prends un taxi-moto. C'est plus rapide que le bus.", 'taxi-moto,nehme,schneller'),
    ('Le travail', 'Was ist in der Regenzeit auf dem Weg zur Arbeit schwierig?', "Qu'est-ce qui est difficile sur le chemin du travail pendant la saison des pluies ?", 'In der Regenzeit sind die Straßen oft voll Wasser, und es gibt viel Verkehr.', "Pendant la saison des pluies, les rues sont souvent pleines d'eau et il y a beaucoup de circulation.", 'regenzeit,straßen,verkehr'),
    ('Le travail', 'Welche Berufe sind in Kamerun sehr beliebt?', 'Quels métiers sont très populaires au Cameroun ?', 'Ich glaube, in Kamerun sind Händler, Lehrer und Fahrer sehr beliebt.', "Je crois qu'au Cameroun, les commerçants, les enseignants et les chauffeurs sont très populaires.", 'kamerun,händler,beliebt'),
    ('Le travail', 'Wie ist es, in Yaoundé einen Job zu finden?', 'Comment est-ce de trouver un emploi à Yaoundé ?', 'Ich finde, es ist nicht leicht, in Yaoundé einen Job zu finden.', "Je trouve qu'il n'est pas facile de trouver un emploi à Yaoundé.", 'job,finden,leicht'),
    ('Le travail', 'Was würdest du ändern, wenn du Chef wärst?', 'Que changerais-tu si tu étais chef ?', 'Wenn ich Chef wäre, würde ich mehr Pausen erlauben.', "Si j'étais chef, j'autoriserais plus de pauses.", 'chef,wäre,würde,pausen'),
    ('Le travail', 'Würdest du weiterarbeiten, wenn du viel Geld hättest?', "Continuerais-tu à travailler si tu avais beaucoup d'argent ?", 'Ja, ich würde weiterarbeiten, denn sonst wäre es mir langweilig.', "Oui, je continuerais à travailler, car sinon je m'ennuierais.", 'weiterarbeiten,würde,langweilig'),
    ('Le travail', 'Welche Vorteile hat es, selbstständig zu sein?', "Quels sont les avantages d'être indépendant ?", 'Ein Vorteil ist, dass ich selbst entscheiden und meine Zeit frei einteilen kann.', "Un avantage, c'est que je peux décider moi-même et organiser mon temps librement.", 'vorteil,entscheiden,zeit,frei'),
    ('Le travail', 'Was ist schwierig, wenn man ein eigenes Geschäft hat?', "Qu'est-ce qui est difficile quand on a son propre commerce ?", 'Ich finde es schwierig, dass nicht jeden Tag viele Kunden kommen.', 'Je trouve difficile que les clients ne soient pas nombreux chaque jour.', 'schwierig,kunden,kommen'),
    ('Le travail', 'Was war dein schönstes Erlebnis bei der Arbeit?', 'Quel a été ton plus beau souvenir au travail ?', 'Mein schönstes Erlebnis war, als unser Team einen großen Auftrag bekommen hat.', "Mon plus beau souvenir, c'est quand notre équipe a obtenu une grosse commande.", 'erlebnis,auftrag,schönstes'),
    ('Le travail', 'Welches Computerprogramm hast du dieses Jahr gelernt?', 'Quel logiciel as-tu appris cette année ?', 'Dieses Jahr habe ich Excel gelernt. Jetzt kann ich Tabellen machen.', "Cette année, j'ai appris Excel. Maintenant, je sais faire des tableaux.", 'excel,gelernt,tabellen'),
    ('Le travail', 'Möchtest du nächstes Jahr einen Kurs für deine Arbeit besuchen?', "Voudrais-tu suivre un cours pour ton travail l'année prochaine ?", 'Ja, nächstes Jahr möchte ich einen Englischkurs besuchen.', "Oui, l'année prochaine, je voudrais suivre un cours d'anglais.", 'kurs,nächstes,englischkurs'),
    ('Le travail', 'Warum möchtest du für deine Arbeit Deutsch lernen?', "Pourquoi veux-tu apprendre l'allemand pour ton travail ?", 'Ich lerne Deutsch, weil ich später in Deutschland arbeiten möchte.', "J'apprends l'allemand parce que je voudrais plus tard travailler en Allemagne.", 'deutsch,deutschland,arbeiten'),
    ('Apprendre', 'Gehst du zur Schule oder zur Universität?', "Vas-tu à l'école ou à l'université ?", 'Ich gehe zur Universität in Yaoundé und studiere dort Wirtschaft.', "Je vais à l'université à Yaoundé et j'y étudie l'économie.", 'universität,gehe,yaoundé,studiere'),
    ('Apprendre', 'Wie heißt deine Schule?', "Comment s'appelle ton école ?", 'Meine Schule heißt Lycée Bilingue und liegt nicht weit vom Markt.', "Mon école s'appelle Lycée Bilingue et se trouve non loin du marché.", 'schule,heißt,lycée,markt'),
    ('Apprendre', 'Wie lange lernst du schon Deutsch?', "Depuis combien de temps apprends-tu déjà l'allemand ?", 'Ich lerne seit sechs Monaten Deutsch, und es macht mir viel Spaß.', "J'apprends l'allemand depuis six mois et cela me plaît beaucoup.", 'seit,monaten,spaß,deutsch'),
    ('Apprendre', 'Wie heißt dein Deutschlehrer?', "Comment s'appelle ton professeur d'allemand ?", 'Mein Deutschlehrer heißt Herr Fouda. Er ist sehr geduldig.', "Mon professeur d'allemand s'appelle Monsieur Fouda. Il est très patient.", 'deutschlehrer,heißt,geduldig'),
    ('Apprendre', 'Wie viele Schüler sind in deiner Klasse?', "Combien d'élèves y a-t-il dans ta classe ?", 'In meiner Klasse sind ungefähr sechzig Schüler. Es ist sehr voll.', 'Dans ma classe, il y a environ soixante élèves. La classe est bondée.', 'klasse,schüler,sechzig,voll'),
    ('Apprendre', 'Welches Fach magst du am liebsten?', 'Quelle matière préfères-tu ?', 'Ich mag Mathe am liebsten, weil ich gern rechne.', "Ma matière préférée est les maths, parce que j'aime calculer.", 'mathe,rechne,liebsten'),
    ('Apprendre', 'Hast du heute Hausaufgaben?', "As-tu des devoirs aujourd'hui ?", 'Ja, ich habe heute Hausaufgaben in Geschichte und Englisch.', "Oui, j'ai des devoirs aujourd'hui en histoire et en anglais.", 'hausaufgaben,englisch,geschichte'),
    ('Apprendre', 'Wann machst du normalerweise deine Hausaufgaben?', 'Quand fais-tu normalement tes devoirs ?', 'Ich mache meine Hausaufgaben am Abend, nach dem Essen.', 'Je fais mes devoirs le soir, après le repas.', 'hausaufgaben,abend,essen,mache'),
    ('Apprendre', 'Wie kommst du zur Schule?', "Comment vas-tu à l'école ?", 'Ich fahre mit dem Taxi zur Schule, aber manchmal gehe ich zu Fuß.', "Je vais à l'école en taxi, mais parfois j'y vais à pied.", 'taxi,fahre,fuß'),
    ('Apprendre', 'Um wie viel Uhr beginnt dein Unterricht?', 'À quelle heure commence ton cours ?', 'Mein Unterricht beginnt um halb acht.', 'Mon cours commence à sept heures et demie.', 'unterricht,beginnt,acht,halb'),
    ('Apprendre', 'Wo lernst du am liebsten Deutsch?', "Où préfères-tu apprendre l'allemand ?", 'Ich lerne am liebsten in meinem Zimmer, weil es dort ruhig ist.', "Je préfère apprendre dans ma chambre, parce qu'il y fait calme.", 'lerne,zimmer,ruhig'),
    ('Apprendre', 'Hast du ein Wörterbuch?', 'As-tu un dictionnaire ?', 'Ja, ich habe ein Wörterbuch auf meinem Handy. Es ist sehr praktisch.', "Oui, j'ai un dictionnaire sur mon téléphone. C'est très pratique.", 'wörterbuch,handy,praktisch'),
    ('Apprendre', 'Was ist dein Lieblingsbuch?', 'Quel est ton livre préféré ?', 'Mein Lieblingsbuch ist ein Abenteuerroman. Ich habe ihn dreimal gelesen.', "Mon livre préféré est un roman d'aventures. Je l'ai lu trois fois.", 'lieblingsbuch,abenteuerroman,gelesen'),
    ('Apprendre', 'Liest du gern Bücher?', 'Aimes-tu lire des livres ?', 'Ja, ich lese gern Bücher, besonders Krimis und Comics.', "Oui, j'aime lire des livres, surtout des polars et des bandes dessinées.", 'lese,krimis,comics,bücher'),
    ('Apprendre', 'Wie oft lernst du Deutsch in der Woche?', "Combien de fois par semaine apprends-tu l'allemand ?", 'Ich lerne zweimal in der Woche Deutsch, jeweils zwei Stunden.', "J'apprends l'allemand deux fois par semaine, deux heures à chaque fois.", 'woche,zweimal,stunden,lerne'),
    ('Apprendre', 'Was ist für dich in Deutsch am schwersten?', "Qu'est-ce qui est le plus difficile pour toi en allemand ?", 'Am schwersten sind für mich die Artikel: der, die oder das?', 'Le plus difficile pour moi, ce sont les articles : der, die ou das ?', 'artikel,schwersten,schwer'),
    ('Apprendre', 'Wie findest du die deutsche Aussprache?', 'Comment trouves-tu la prononciation allemande ?', 'Die Aussprache finde ich schwierig, aber sehr interessant.', 'Je trouve la prononciation difficile, mais très intéressante.', 'aussprache,schwierig,interessant'),
    ('Apprendre', 'Sprichst du gern Deutsch?', 'Aimes-tu parler allemand ?', 'Ja, ich spreche gern Deutsch, aber ich mache noch viele Fehler.', "Oui, j'aime parler allemand, mais je fais encore beaucoup de fautes.", 'spreche,gern,fehler'),
    ('Apprendre', 'Welche Sprachen sprichst du?', 'Quelles langues parles-tu ?', 'Ich spreche Französisch, Englisch und ein bisschen Deutsch.', 'Je parle français, anglais et un peu allemand.', 'spreche,französisch,englisch,bisschen'),
    ('Apprendre', 'Was ist deine Muttersprache?', 'Quelle est ta langue maternelle ?', 'Meine Muttersprache ist Ewondo, aber zu Hause sprechen wir auch Französisch.', "Ma langue maternelle est l'ewondo, mais à la maison nous parlons aussi français.", 'muttersprache,ewondo,französisch'),
    ('Apprendre', 'Wie sagt man auf Deutsch „merci“?', 'Comment dit-on « merci » en allemand ?', 'Man sagt „danke“ oder „vielen Dank“. Das ist sehr höflich.', "On dit « danke » ou « vielen Dank ». C'est très poli.", 'danke,dank,sagt'),
    ('Apprendre', 'Wie viele neue Wörter lernst du pro Tag?', 'Combien de nouveaux mots apprends-tu par jour ?', 'Ich lerne jeden Tag ungefähr zehn neue Wörter.', "J'apprends environ dix nouveaux mots chaque jour.", 'wörter,zehn,lerne'),
    ('Apprendre', 'Wie lernst du neue Vokabeln?', 'Comment apprends-tu le nouveau vocabulaire ?', 'Ich schreibe die Vokabeln auf Karten und wiederhole sie jeden Abend.', "J'écris les mots de vocabulaire sur des cartes et je les répète chaque soir.", 'vokabeln,karten,wiederhole,schreibe'),
    ('Apprendre', 'Welche Fremdsprache möchtest du noch lernen?', 'Quelle langue étrangère voudrais-tu encore apprendre ?', 'Ich möchte noch Spanisch lernen, weil ich gern nach Spanien reisen will.', "Je voudrais encore apprendre l'espagnol, parce que je veux voyager en Espagne.", 'spanisch,möchte,spanien,reisen'),
    ('Apprendre', 'Hörst du manchmal deutsche Musik?', 'Écoutes-tu parfois de la musique allemande ?', 'Ja, ich höre manchmal deutsche Lieder und lerne dabei neue Wörter.', "Oui, j'écoute parfois des chansons allemandes et j'apprends ainsi de nouveaux mots.", 'lieder,höre,wörter'),
    ('Apprendre', 'Lernst du mit einem Computer oder mit dem Handy?', 'Apprends-tu avec un ordinateur ou avec le téléphone ?', 'Ich lerne mit dem Handy, denn einen Computer habe ich nicht.', "J'apprends avec le téléphone, car je n'ai pas d'ordinateur.", 'handy,computer,lerne'),
    ('Apprendre', 'Welche Fächer hast du am Montag?', 'Quelles matières as-tu le lundi ?', 'Am Montag habe ich Mathe, Französisch und Geschichte.', "Le lundi, j'ai maths, français et histoire.", 'montag,mathe,geschichte,französisch'),
    ('Apprendre', 'Welcher Wochentag gefällt dir in der Schule am besten?', "Quel jour de la semaine préfères-tu à l'école ?", 'Am besten gefällt mir der Freitag, denn dann haben wir Sport.', 'Mon jour préféré est le vendredi, car nous avons du sport.', 'freitag,sport,besten'),
    ('Apprendre', 'Was machst du in der Pause?', 'Que fais-tu pendant la récréation ?', 'In der Pause esse ich Beignets und spreche mit meinen Freunden.', 'Pendant la récréation, je mange des beignets et je parle avec mes amis.', 'pause,beignets,freunden,esse'),
    ('Apprendre', 'Hast du viele Freunde in deiner Klasse?', "As-tu beaucoup d'amis dans ta classe ?", 'Ja, ich habe fünf gute Freunde in meiner Klasse. Wir helfen uns oft.', "Oui, j'ai cinq bons amis dans ma classe. Nous nous aidons souvent.", 'freunde,klasse,helfen'),
    ('Apprendre', 'Warum lernst du Deutsch?', "Pourquoi apprends-tu l'allemand ?", 'Ich lerne Deutsch, weil ich in Deutschland studieren möchte.', "J'apprends l'allemand parce que je voudrais étudier en Allemagne.", 'deutsch,deutschland,studieren,möchte'),
    ('Apprendre', 'Warum möchtest du das Goethe-Zertifikat machen?', 'Pourquoi veux-tu passer le certificat Goethe ?', 'Mit dem Zertifikat kann ich mich an einer deutschen Uni bewerben.', 'Avec le certificat, je peux postuler dans une université allemande.', 'zertifikat,uni,bewerben'),
    ('Apprendre', 'Was musst du bei der Goethe-Prüfung machen?', "Que dois-tu faire à l'examen Goethe ?", 'Bei der Prüfung muss ich lesen, hören, schreiben und sprechen.', "À l'examen, je dois lire, écouter, écrire et parler.", 'prüfung,muss,lesen,sprechen'),
    ('Apprendre', 'Hast du Angst vor Prüfungen?', 'As-tu peur des examens ?', 'Ja, ich habe ein bisschen Angst, besonders vor der mündlichen Prüfung.', "Oui, j'ai un peu peur, surtout de l'examen oral.", 'angst,prüfung,mündlichen'),
    ('Apprendre', 'Wie verbringst du den Abend vor einer Prüfung?', 'Comment passes-tu la soirée avant un examen ?', 'Am Abend vor einer Prüfung lese ich meine Notizen und gehe früh ins Bett.', "La veille d'un examen, je relis mes notes et je me couche tôt.", 'prüfung,notizen,bett'),
    ('Apprendre', 'Wann ist deine nächste Prüfung?', 'Quand est ton prochain examen ?', 'Meine nächste Prüfung ist im Dezember. Ich muss noch viel lernen.', 'Mon prochain examen est en décembre. Je dois encore beaucoup apprendre.', 'prüfung,dezember,nächste,lernen'),
    ('Apprendre', 'Wenn du ein Wort nicht verstehst, was machst du?', 'Si tu ne comprends pas un mot, que fais-tu ?', 'Ich frage meinen Lehrer oder suche das Wort im Wörterbuch.', 'Je demande à mon professeur ou je cherche le mot dans le dictionnaire.', 'wort,frage,wörterbuch,lehrer'),
    ('Apprendre', 'Wie reagierst du, wenn du einen Fehler machst?', 'Comment réagis-tu quand tu fais une faute ?', 'Ich lache und versuche es noch einmal. Fehler sind normal.', "Je ris et j'essaie encore une fois. Les fautes sont normales.", 'fehler,lache,versuche'),
    ('Apprendre', 'Was kannst du schon gut auf Deutsch sagen?', 'Que sais-tu déjà bien dire en allemand ?', 'Ich kann mich vorstellen und über meine Familie sprechen.', 'Je sais me présenter et parler de ma famille.', 'kann,vorstellen,familie'),
    ('Apprendre', 'Kannst du auf Deutsch bis hundert zählen?', "Peux-tu compter jusqu'à cent en allemand ?", 'Ja, ich kann bis hundert zählen, aber die großen Zahlen sind schwer.', "Oui, je peux compter jusqu'à cent, mais les grands nombres sont difficiles.", 'hundert,zählen,zahlen'),
    ('Apprendre', 'Möchtest du in Deutschland studieren?', 'Voudrais-tu étudier en Allemagne ?', 'Ja, ich möchte in Berlin Informatik studieren.', "Oui, je voudrais étudier l'informatique à Berlin.", 'studieren,berlin,informatik,möchte'),
    ('Apprendre', 'Welche Stadt in Deutschland möchtest du gern besuchen?', "Quelle ville d'Allemagne aimerais-tu visiter ?", 'Ich möchte gern München besuchen, denn die Alpen sind dort ganz in der Nähe.', "J'aimerais visiter Munich, car les Alpes sont tout près de là.", 'münchen,besuchen,alpen,möchte'),
    ('Apprendre', 'Was weißt du über Deutschland?', "Que sais-tu de l'Allemagne ?", 'Deutschland liegt in Europa. Ich weiß, dass es dort im Winter sehr kalt ist.', "L'Allemagne se trouve en Europe. Je sais qu'il y fait très froid en hiver.", 'europa,kalt,winter,deutschland'),
    ('Apprendre', 'Welches deutsche Wort gefällt dir besonders gut?', 'Quel mot allemand te plaît particulièrement ?', 'Mir gefällt das Wort „Schmetterling“. Es klingt lustig.', "J'aime le mot « Schmetterling ». Il sonne drôle.", 'wort,gefällt,schmetterling,klingt'),
    ('Apprendre', 'Wie stellst du dir das Studium in Deutschland vor?', 'Comment imagines-tu les études en Allemagne ?', 'Ich stelle mir das Studium schwer vor, aber auch sehr interessant.', "J'imagine les études difficiles, mais aussi très intéressantes.", 'studium,schwer,interessant'),
    ('Apprendre', 'Was möchtest du studieren?', 'Que voudrais-tu étudier ?', 'Ich möchte Medizin studieren, weil ich kranken Menschen helfen will.', 'Je voudrais étudier la médecine, parce que je veux aider les malades.', 'medizin,studieren,helfen'),
    ('Apprendre', 'Was willst du später werden?', 'Que veux-tu devenir plus tard ?', 'Später will ich Ingenieur werden, weil ich Technik interessant finde.', 'Plus tard, je veux devenir ingénieur, parce que je trouve la technique intéressante.', 'ingenieur,werden,technik'),
    ('Apprendre', 'Was machst du nach der Schule?', "Que fais-tu après l'école ?", 'Nach der Schule gehe ich nach Hause und helfe meiner Mutter beim Kochen.', "Après l'école, je rentre à la maison et j'aide ma mère à faire la cuisine.", 'schule,mutter,helfe,kochen'),
    ('Apprendre', 'Welche Pläne hast du morgen nach dem Unterricht?', 'Quels projets as-tu demain après le cours ?', 'Morgen nach dem Unterricht treffe ich meine Freunde und wir lernen zusammen.', 'Demain après le cours, je retrouve mes amis et nous apprenons ensemble.', 'morgen,unterricht,treffe,zusammen'),
    ('Apprendre', 'Was lernst du am Wochenende?', "Qu'apprends-tu le week-end ?", 'Am Wochenende lerne ich Vokabeln und schaue deutsche Videos.', "Le week-end, j'apprends du vocabulaire et je regarde des vidéos allemandes.", 'wochenende,vokabeln,videos,lerne'),
    ('Apprendre', 'Was findest du am Deutschlernen am schönsten?', "Qu'est-ce que tu trouves de plus beau dans l'apprentissage de l'allemand ?", 'Am schönsten finde ich es, wenn ich einen ganzen Satz verstehe.', "Ce que je trouve le plus beau, c'est quand je comprends une phrase entière.", 'schönsten,satz,verstehe,finde'),
    ('Apprendre', 'Wie findest du Hausaufgaben?', 'Que penses-tu des devoirs à la maison ?', 'Ich finde Hausaufgaben nützlich, aber manchmal sind sie zu lang.', 'Je trouve les devoirs utiles, mais parfois ils sont trop longs.', 'hausaufgaben,nützlich,finde'),
    ('Apprendre', 'Was findest du schwieriger: Hören oder Sprechen?', "Qu'est-ce qui est plus difficile selon toi : écouter ou parler ?", 'Ich finde Hören schwieriger, weil die Leute so schnell sprechen.', "Je trouve qu'écouter est plus difficile, parce que les gens parlent si vite.", 'hören,sprechen,schwieriger,schnell'),
    ('Apprendre', 'Was hast du gestern in der Schule gemacht?', "Qu'as-tu fait hier à l'école ?", 'Gestern hatten wir Mathe, und in der Pause habe ich Fußball gespielt.', "Hier, nous avons eu maths, et pendant la récréation j'ai joué au football.", 'gestern,mathe,fußball,gespielt'),
    ('Apprendre', 'Hast du letzte Woche einen Test geschrieben?', 'As-tu passé un contrôle la semaine dernière ?', 'Ja, letzte Woche habe ich einen Test in Geschichte geschrieben.', "Oui, la semaine dernière, j'ai passé un contrôle d'histoire.", 'test,geschrieben,geschichte'),
    ('Apprendre', 'Wo hast du zum ersten Mal Deutsch gehört?', "Où as-tu entendu de l'allemand pour la première fois ?", 'Ich habe zum ersten Mal in einem Film Deutsch gehört. Es hat mir gleich gefallen.', "J'ai entendu de l'allemand pour la première fois dans un film. Ça m'a tout de suite plu.", 'gehört,film,gefallen'),
    ('Apprendre', 'Mit wem hast du heute Deutsch gesprochen?', "Avec qui as-tu parlé allemand aujourd'hui ?", 'Heute habe ich mit meiner Schwester Deutsch gesprochen.', "Aujourd'hui, j'ai parlé allemand avec ma sœur.", 'heute,schwester,gesprochen'),
    ('Apprendre', 'Welches Buch hast du zuletzt gelesen?', 'Quel livre as-tu lu en dernier ?', 'Zuletzt habe ich ein Buch über die Geschichte von Kamerun gelesen.', "Dernièrement, j'ai lu un livre sur l'histoire du Cameroun.", 'buch,gelesen,geschichte,kamerun'),
    ('Apprendre', 'Hast du schon einmal eine Prüfung nicht bestanden?', 'As-tu déjà raté un examen ?', 'Ja, einmal habe ich eine Mathe-Prüfung nicht bestanden. Danach habe ich mehr gelernt.', "Oui, une fois j'ai raté un examen de maths. Ensuite, j'ai plus travaillé.", 'prüfung,bestanden,gelernt'),
    ('Apprendre', 'Hast du am Wochenende gelernt oder dich ausgeruht?', "As-tu étudié ou t'es-tu reposé pendant le week-end ?", 'Am Samstag habe ich gelernt, und am Sonntag habe ich mich ausgeruht.', "Samedi, j'ai étudié, et dimanche, je me suis reposé.", 'gelernt,ausgeruht,sonntag'),
    ('Apprendre', 'Wie viele Stunden hast du gestern gelernt?', "Combien d'heures as-tu étudié hier ?", 'Gestern habe ich drei Stunden gelernt. Danach war ich sehr müde.', "Hier, j'ai étudié trois heures. Après, j'étais très fatigué.", 'stunden,gelernt,drei,müde'),
    ('Apprendre', 'Wie war dein erster Schultag?', "Comment s'est passé ton premier jour d'école ?", 'Mein erster Schultag war aufregend. Ich war nervös, aber die Lehrerin war nett.', "Mon premier jour d'école était plein d'émotions. J'étais nerveux, mais l'institutrice était gentille.", 'schultag,aufregend,nervös,nett'),
    ('Apprendre', 'Hast du schon einmal ein Referat gehalten?', 'As-tu déjà fait un exposé ?', 'Ja, ich habe ein Referat über Elefanten gehalten. Es hat gut geklappt.', "Oui, j'ai fait un exposé sur les éléphants. Cela s'est bien passé.", 'referat,gehalten,elefanten'),
    ('Apprendre', 'Wie hast du deine Freunde in der Klasse kennengelernt?', 'Comment as-tu fait la connaissance de tes amis dans la classe ?', 'Wir haben uns am ersten Schultag in der Klasse kennengelernt.', "Nous avons fait connaissance le premier jour d'école dans la classe.", 'kennengelernt,klasse,schultag'),
    ('Apprendre', 'Wie viele Punkte hast du im letzten Test bekommen?', 'Combien de points as-tu obtenus au dernier contrôle ?', 'Ich habe fünfzehn von zwanzig Punkten bekommen. Ich war zufrieden.', "J'ai obtenu quinze points sur vingt. J'étais satisfait.", 'punkte,fünfzehn,zwanzig,bekommen'),
    ('Apprendre', 'Bist du schon einmal in Deutschland gewesen?', 'As-tu déjà été en Allemagne ?', 'Nein, ich bin noch nie in Deutschland gewesen, aber ich möchte bald dorthin reisen.', 'Non, je ne suis encore jamais allé en Allemagne, mais je voudrais bientôt y voyager.', 'deutschland,gewesen,reisen'),
    ('Apprendre', 'Welches Wort hast du zuletzt vergessen?', 'Quel mot as-tu oublié dernièrement ?', 'Zuletzt habe ich das Wort „Bahnhof“ vergessen. Ich musste im Wörterbuch suchen.', "Dernièrement, j'ai oublié le mot « Bahnhof ». J'ai dû chercher dans le dictionnaire.", 'wort,vergessen,bahnhof'),
    ('Apprendre', 'Wie hast du früher Französisch gelernt?', 'Comment as-tu appris le français autrefois ?', 'In der Grundschule habe ich Französisch mit Liedern und Spielen gelernt.', "À l'école primaire, j'ai appris le français avec des chansons et des jeux.", 'französisch,grundschule,liedern,spielen'),
    ('Apprendre', 'Wer hat dir beim Lernen geholfen?', "Qui t'a aidé à apprendre ?", 'Mein großer Bruder hat mir oft bei den Hausaufgaben geholfen.', "Mon grand frère m'a souvent aidé pour les devoirs.", 'bruder,geholfen,hausaufgaben'),
    ('Apprendre', 'Hast du heute schon Deutsch geübt?', "As-tu déjà pratiqué l'allemand aujourd'hui ?", 'Ja, ich habe heute schon eine Stunde mit einer App geübt.', "Oui, j'ai déjà pratiqué une heure avec une appli aujourd'hui.", 'geübt,app,stunde,heute'),
    ('Apprendre', 'Wann bist du heute aufgestanden?', "À quelle heure t'es-tu levé aujourd'hui ?", 'Heute bin ich um sechs Uhr aufgestanden, denn mein Unterricht beginnt früh.', "Aujourd'hui, je me suis levé à six heures, car mon cours commence tôt.", 'aufgestanden,sechs,uhr'),
    ('Apprendre', 'Wo hast du deine Schulbücher gekauft?', 'Où as-tu acheté tes livres scolaires ?', 'Ich habe meine Schulbücher auf dem Markt in Mokolo gekauft.', "J'ai acheté mes livres scolaires au marché de Mokolo.", 'schulbücher,markt,gekauft,mokolo'),
    ('Apprendre', 'Wie lange hast du heute für den Schulweg gebraucht?', "Combien de temps as-tu mis aujourd'hui pour aller à l'école ?", 'Heute habe ich eine halbe Stunde gebraucht, denn es war viel Verkehr.', "Aujourd'hui, j'ai mis une demi-heure, car il y avait beaucoup de circulation.", 'stunde,gebraucht,verkehr'),
    ('Apprendre', 'Erzähl mir von deiner Schule.', 'Parle-moi de ton école.', 'Meine Schule ist groß und hat einen schönen Hof. Wir sind über tausend Schüler.', 'Mon école est grande et a une belle cour. Nous sommes plus de mille élèves.', 'schule,groß,hof,schüler'),
    ('Apprendre', 'Erzähl mir von deinem Lieblingslehrer.', 'Parle-moi de ton professeur préféré.', 'Mein Lieblingslehrer ist der Mathelehrer. Er erklärt alles langsam und ist immer freundlich.', 'Mon professeur préféré est le professeur de maths. Il explique tout lentement et il est toujours aimable.', 'lieblingslehrer,erklärt,freundlich,langsam'),
    ('Apprendre', 'Beschreibe dein Klassenzimmer.', 'Décris ta salle de classe.', 'In meinem Klassenzimmer gibt es viele Tische, Stühle und eine große Tafel.', 'Dans ma salle de classe, il y a beaucoup de tables, de chaises et un grand tableau.', 'klassenzimmer,tafel,tische,stühle'),
    ('Apprendre', 'Beschreibe deinen Lernplatz zu Hause.', "Décris ton coin d'étude à la maison.", 'Mein Lernplatz ist ein kleiner Tisch in meinem Zimmer. Dort liegen meine Hefte und mein Handy.', "Mon coin d'étude est une petite table dans ma chambre. Mes cahiers et mon téléphone s'y trouvent.", 'lernplatz,tisch,hefte,zimmer'),
    ('Apprendre', 'Beschreibe einen typischen Tag an der Uni.', "Décris une journée typique à l'université.", 'Ich gehe zur Vorlesung, esse mittags in der Mensa und lerne nachmittags in der Bibliothek.', "Je vais en cours magistral, je mange à midi au restaurant universitaire et j'étudie l'après-midi à la bibliothèque.", 'vorlesung,mensa,bibliothek'),
    ('Apprendre', 'Du verstehst im Deutschkurs etwas nicht. Was sagst du?', "Tu ne comprends pas quelque chose au cours d'allemand. Que dis-tu ?", 'Ich sage: „Können Sie das bitte noch einmal sagen?“', "Je dis : « Pouvez-vous répéter cela, s'il vous plaît ? »", 'bitte,einmal,können'),
    ('Apprendre', 'Du triffst deinen Lehrer auf der Straße. Was sagst du?', 'Tu rencontres ton professeur dans la rue. Que dis-tu ?', 'Ich sage: „Guten Tag, Herr Nkou! Wie geht es Ihnen?“', 'Je dis : « Bonjour, Monsieur Nkou ! Comment allez-vous ? »', 'guten,ihnen,herr'),
    ('Apprendre', 'Du möchtest in der Bibliothek ein Buch ausleihen. Was sagst du?', 'Tu veux emprunter un livre à la bibliothèque. Que dis-tu ?', 'Ich sage: „Entschuldigung, ich möchte dieses Buch ausleihen. Wie lange darf ich es behalten?“', 'Je dis : « Excusez-moi, je voudrais emprunter ce livre. Combien de temps puis-je le garder ? »', 'buch,ausleihen,möchte,behalten'),
    ('Apprendre', 'Du bist auf dem Campus und suchst die Mensa. Was fragst du?', 'Tu es sur le campus et tu cherches le restaurant universitaire. Que demandes-tu ?', 'Ich frage: „Entschuldigung, wo ist die Mensa, bitte?“', "Je demande : « Excusez-moi, où est le restaurant universitaire, s'il vous plaît ? »", 'mensa,entschuldigung,bitte'),
    ('Apprendre', 'Dein Freund hat die Prüfung bestanden. Wie gratulierst du ihm?', "Ton ami a réussi l'examen. Comment le félicites-tu ?", 'Ich gratuliere ihm und sage: „Herzlichen Glückwunsch! Das hast du super gemacht.“', 'Je le félicite et je dis : « Félicitations ! Tu as super bien réussi. »', 'gratuliere,glückwunsch,herzlichen,super'),
    ('Apprendre', 'Du kommst zu spät zum Unterricht. Was sagst du?', 'Tu arrives en retard au cours. Que dis-tu ?', 'Ich sage: „Es tut mir leid, dass ich zu spät bin. Das Taxi hatte eine Panne.“', "Je dis : « Je suis désolé d'être en retard. Le taxi est tombé en panne. »", 'leid,spät,taxi,panne'),
    ('Apprendre', 'Was würdest du in Deutschland zuerst machen?', 'Que ferais-tu en premier en Allemagne ?', 'Zuerst würde ich ein Café besuchen und deutschen Kuchen probieren.', "D'abord, j'irais dans un café et je goûterais du gâteau allemand.", 'würde,café,kuchen,besuchen'),
    ('Apprendre', 'In welcher Stadt würdest du gern studieren?', 'Dans quelle ville aimerais-tu étudier ?', 'Ich würde gern in Heidelberg studieren, weil die Stadt sehr schön ist.', "J'aimerais étudier à Heidelberg, parce que la ville est très belle.", 'heidelberg,würde,studieren,stadt'),
    ('Apprendre', 'Was brauchst du, um in Deutschland zu studieren?', 'De quoi as-tu besoin pour étudier en Allemagne ?', 'Ich brauche ein Visum, ein Zeugnis und ein Deutschzertifikat.', "J'ai besoin d'un visa, d'un diplôme et d'un certificat d'allemand.", 'visum,zeugnis,brauche'),
    ('Apprendre', 'Wie viel Geld brauchst du ungefähr im Monat in Deutschland?', "De combien d'argent as-tu besoin environ par mois en Allemagne ?", 'Ich glaube, ich brauche ungefähr tausend Euro im Monat.', "Je crois que j'ai besoin d'environ mille euros par mois.", 'euro,tausend,brauche,monat'),
    ('Apprendre', 'Wo möchtest du in Deutschland wohnen, in einer WG oder allein?', 'Où voudrais-tu habiter en Allemagne, en colocation ou seul ?', 'Ich möchte in einer WG wohnen, denn dort finde ich schnell neue Freunde.', "Je voudrais habiter en colocation, car j'y trouve vite de nouveaux amis.", 'wg,wohnen,freunde,schnell'),
    ('Apprendre', 'Welche Sprache findest du am schönsten?', 'Quelle langue trouves-tu la plus belle ?', 'Ich finde Italienisch am schönsten, weil es wie Musik klingt.', "Je trouve l'italien le plus beau, parce qu'il sonne comme de la musique.", 'italienisch,schönsten,musik,klingt'),
    ('Apprendre', 'Welche Sprache sprichst du auf dem Markt in Yaoundé?', 'Quelle langue parles-tu au marché de Yaoundé ?', 'Auf dem Markt spreche ich Französisch und manchmal ein bisschen Pidgin.', 'Au marché, je parle français et parfois un peu de pidgin.', 'markt,französisch,pidgin,spreche'),
    ('Apprendre', 'Findest du Deutsch schwieriger als Englisch?', "Trouves-tu l'allemand plus difficile que l'anglais ?", 'Ja, ich finde Deutsch schwieriger, weil die Grammatik kompliziert ist.', "Oui, je trouve l'allemand plus difficile, parce que la grammaire est compliquée.", 'schwieriger,grammatik,kompliziert'),
    ('Apprendre', 'Lernst du besser allein oder mit Freunden?', 'Apprends-tu mieux seul ou avec des amis ?', 'Ich lerne besser mit Freunden, denn dann sprechen wir viel zusammen.', "J'apprends mieux avec des amis, car alors nous parlons beaucoup ensemble.", 'freunden,besser,sprechen,zusammen'),
    ('Apprendre', 'Hörst du lieber Podcasts oder liest du lieber Texte?', 'Préfères-tu écouter des podcasts ou lire des textes ?', 'Ich höre lieber Podcasts, weil ich dabei die Aussprache übe.', "Je préfère écouter des podcasts, parce que je m'entraîne ainsi à la prononciation.", 'podcasts,höre,aussprache,übe'),
    ('Apprendre', 'Was ist dein größtes Ziel für nächstes Jahr?', "Quel est ton plus grand objectif pour l'année prochaine ?", 'Mein größtes Ziel ist die A2-Prüfung. Ich möchte sie unbedingt bestehen.', "Mon plus grand objectif est l'examen A2. Je veux absolument le réussir.", 'ziel,prüfung,bestehen'),
    ('Apprendre', 'Was motiviert dich am meisten zum Lernen?', "Qu'est-ce qui te motive le plus à apprendre ?", 'Am meisten motiviert mich mein Traum, in Europa zu arbeiten.', "Ce qui me motive le plus, c'est mon rêve de travailler en Europe.", 'motiviert,traum,europa,arbeiten'),
    ('Apprendre', 'Wie motivierst du dich, wenn du müde bist?', 'Comment te motives-tu quand tu es fatigué ?', 'Ich höre Musik, trinke einen Kaffee und denke an meine Ziele.', "J'écoute de la musique, je bois un café et je pense à mes objectifs.", 'musik,kaffee,ziele'),
    ('Apprendre', 'Hast du Lust, nach dem Kurs mit mir zu üben?', "As-tu envie de t'entraîner avec moi après le cours ?", 'Ja, gern! Nach dem Kurs habe ich Zeit, und wir können zusammen üben.', "Oui, volontiers ! Après le cours, j'ai le temps et nous pouvons nous entraîner ensemble.", 'zeit,üben,zusammen,gern'),
    ('Apprendre', 'Wie sieht für dich ein perfekter Lerntag aus?', "À quoi ressemble pour toi une journée d'étude parfaite ?", 'Ein perfekter Lerntag beginnt mit einem Kaffee. Ich lerne zwei Stunden und mache danach Sport.', "Une journée d'étude parfaite commence par un café. J'étudie deux heures et je fais ensuite du sport.", 'lerntag,kaffee,stunden,sport'),
    ('Loisirs et sport', 'Was machst du gern in deiner Freizeit?', 'Que fais-tu volontiers pendant ton temps libre ?', 'In meiner Freizeit höre ich gern Musik und gehe spazieren.', "Pendant mon temps libre, j'aime écouter de la musique et me promener.", 'freizeit,musik,spazieren,gern'),
    ('Loisirs et sport', 'Hast du ein Hobby?', 'As-tu un loisir ?', 'Ja, mein Hobby ist Fotografieren. Ich mache gern Fotos mit meinem Handy.', "Oui, mon loisir, c'est la photographie. J'aime prendre des photos avec mon téléphone.", 'hobby,fotografieren,fotos'),
    ('Loisirs et sport', 'Welchen Sport machst du am liebsten?', 'Quel sport préfères-tu pratiquer ?', 'Mein Lieblingssport ist Fußball. Ich spiele jeden Samstag mit meinen Freunden.', 'Mon sport préféré est le football. Je joue tous les samedis avec mes amis.', 'lieblingssport,fußball,spiele'),
    ('Loisirs et sport', 'Schwimmst du gern?', 'Aimes-tu nager ?', 'Ja, ich schwimme sehr gern, vor allem im Schwimmbad.', "Oui, j'aime beaucoup nager, surtout à la piscine.", 'schwimme,gern,schwimmbad'),
    ('Loisirs et sport', 'Wer ist dein Lieblingsspieler?', 'Qui est ton joueur préféré ?', "Mein Lieblingsspieler ist Samuel Eto'o. Er hat viele Tore für Kamerun geschossen.", "Mon joueur préféré est Samuel Eto'o. Il a marqué beaucoup de buts pour le Cameroun.", 'lieblingsspieler,tore,kamerun'),
    ('Loisirs et sport', 'Welche Musik hörst du gern?', 'Quelle musique aimes-tu écouter ?', 'Ich höre gern Afrobeat und Makossa, weil die Musik so fröhlich ist.', "J'écoute volontiers de l'afrobeat et du makossa, parce que la musique est si joyeuse.", 'musik,höre,afrobeat,makossa'),
    ('Loisirs et sport', 'Tanzt du gern?', 'Aimes-tu danser ?', 'Ja, ich tanze sehr gern, besonders auf Partys mit meinen Freunden.', "Oui, j'aime beaucoup danser, surtout aux fêtes avec mes amis.", 'tanze,gern,partys'),
    ('Loisirs et sport', 'Wie oft gehst du ins Kino?', 'À quelle fréquence vas-tu au cinéma ?', 'Ich gehe einmal im Monat ins Kino, meistens mit meiner Schwester.', 'Je vais au cinéma une fois par mois, le plus souvent avec ma sœur.', 'kino,monat,gehe'),
    ('Loisirs et sport', 'Was ist dein Lieblingsfilm?', 'Quel est ton film préféré ?', 'Mein Lieblingsfilm ist ein Actionfilm. Ich habe ihn schon dreimal gesehen.', "Mon film préféré est un film d'action. Je l'ai déjà vu trois fois.", 'lieblingsfilm,actionfilm,gesehen'),
    ('Loisirs et sport', 'Siehst du gern Serien?', 'Aimes-tu regarder des séries ?', 'Ja, ich sehe abends gern Serien auf meinem Handy.', "Oui, j'aime regarder des séries le soir sur mon téléphone.", 'serien,sehe,abends'),
    ('Loisirs et sport', 'Was hast du gestern Abend gemacht?', "Qu'as-tu fait hier soir ?", 'Gestern Abend habe ich mit Freunden Karten gespielt und viel gelacht.', "Hier soir, j'ai joué aux cartes avec des amis et j'ai beaucoup ri.", 'gestern,karten,gespielt,gelacht'),
    ('Loisirs et sport', 'Was liest du gerade?', 'Que lis-tu en ce moment ?', 'Ich lese gerade einen Roman von einer afrikanischen Autorin.', "Je lis en ce moment un roman d'une autrice africaine.", 'lese,roman,autorin'),
    ('Loisirs et sport', 'Welche Spiele spielst du am Wochenende gern?', 'À quels jeux aimes-tu jouer le week-end ?', 'Am Wochenende spiele ich gern Dame und Domino mit meiner Familie.', "Le week-end, j'aime jouer aux dames et au domino avec ma famille.", 'spiele,wochenende,domino,dame'),
    ('Loisirs et sport', 'Ist Kochen für dich ein Hobby?', 'Est-ce que cuisiner est un loisir pour toi ?', 'Ja, Kochen ist mein Hobby. Ich koche gern Ndolé mit Fisch für meine Familie.', "Oui, cuisiner est mon loisir. J'aime cuisiner du ndolé au poisson pour ma famille.", 'kochen,hobby,ndolé,koche'),
    ('Loisirs et sport', 'Was kochst du am liebsten für deine Freunde?', 'Que préfères-tu cuisiner pour tes amis ?', 'Für meine Freunde koche ich am liebsten Reis mit Hähnchen.', "Pour mes amis, ce que je préfère cuisiner, c'est du riz avec du poulet.", 'koche,reis,hähnchen,freunde'),
    ('Loisirs et sport', 'Gehst du gern spazieren?', 'Aimes-tu te promener ?', 'Ja, nach der Arbeit gehe ich gern eine Stunde spazieren.', "Oui, après le travail, j'aime me promener pendant une heure.", 'spazieren,gehe,stunde'),
    ('Loisirs et sport', 'Was machst du normalerweise am Wochenende?', 'Que fais-tu normalement le week-end ?', 'Am Wochenende schlafe ich lange und treffe dann meine Freunde.', 'Le week-end, je dors longtemps et ensuite je retrouve mes amis.', 'wochenende,schlafe,treffe,freunde'),
    ('Loisirs et sport', 'Spielst du lieber Fußball oder Basketball?', 'Préfères-tu jouer au football ou au basket-ball ?', 'Ich spiele lieber Fußball, weil ich schnell laufen kann.', 'Je préfère jouer au football, parce que je peux courir vite.', 'lieber,fußball,spiele,laufen'),
    ('Loisirs et sport', 'Hörst du lieber Radio oder Musik vom Handy?', 'Préfères-tu écouter la radio ou la musique de ton téléphone ?', 'Ich höre lieber Musik vom Handy, denn da kann ich meine Lieder wählen.', 'Je préfère écouter de la musique sur mon téléphone, car là je peux choisir mes chansons.', 'lieber,musik,handy,lieder'),
    ('Loisirs et sport', 'Bleibst du abends lieber zu Hause oder gehst du aus?', 'Le soir, préfères-tu rester à la maison ou sortir ?', 'Abends bleibe ich lieber zu Hause, weil ich nach der Arbeit müde bin.', 'Le soir, je préfère rester à la maison, parce que je suis fatigué après le travail.', 'abends,bleibe,hause,müde'),
    ('Loisirs et sport', 'Machst du lieber Sport allein oder mit Freunden?', 'Préfères-tu faire du sport seul ou avec des amis ?', 'Ich mache lieber Sport mit Freunden, denn zusammen macht es mehr Spaß.', "Je préfère faire du sport avec des amis, car ensemble c'est plus amusant.", 'sport,freunden,zusammen,lieber'),
    ('Loisirs et sport', 'Liest du lieber ein Buch oder eine Zeitschrift?', 'Préfères-tu lire un livre ou un magazine ?', 'Ich lese lieber eine Zeitschrift, weil die Texte kurz sind.', 'Je préfère lire un magazine, parce que les textes sont courts.', 'lese,zeitschrift,lieber,kurz'),
    ('Loisirs et sport', 'Isst du beim Fernsehen lieber Chips oder Erdnüsse?', 'En regardant la télé, préfères-tu manger des chips ou des arachides ?', 'Beim Fernsehen esse ich lieber Erdnüsse, denn ich mag sie sehr.', 'En regardant la télé, je préfère manger des arachides, car je les aime beaucoup.', 'fernsehen,erdnüsse,lieber,esse'),
    ('Loisirs et sport', 'Du triffst einen Freund im Park. Was spielt ihr zusammen?', 'Tu rencontres un ami au parc. À quoi jouez-vous ensemble ?', 'Wir spielen zusammen Frisbee und trinken danach ein kaltes Getränk.', 'Nous jouons ensemble au frisbee, puis nous buvons une boisson fraîche.', 'spielen,frisbee,zusammen'),
    ('Loisirs et sport', 'Du bist im Kino. Was kaufst du zum Film?', "Tu es au cinéma. Qu'achètes-tu pour le film ?", 'Ich kaufe Popcorn und eine Cola, weil das zum Film gehört.', "J'achète du pop-corn et un Coca, parce que ça fait partie du film.", 'popcorn,cola,kaufe'),
    ('Loisirs et sport', 'Du möchtest ins Fitnessstudio gehen. Was fragst du an der Rezeption?', 'Tu veux aller à la salle de sport. Que demandes-tu à la réception ?', 'Ich frage: Wie viel kostet ein Monat, und wann ist das Studio geöffnet?', 'Je demande : combien coûte un mois, et quand la salle est-elle ouverte ?', 'kostet,monat,geöffnet,studio'),
    ('Loisirs et sport', 'Du kaufst Karten für ein Konzert. Was sagst du an der Kasse?', 'Tu achètes des billets pour un concert. Que dis-tu à la caisse ?', 'Guten Tag, ich möchte zwei Karten für das Konzert am Samstag, bitte.', "Bonjour, je voudrais deux billets pour le concert de samedi, s'il vous plaît.", 'karten,konzert,möchte,bitte'),
    ('Loisirs et sport', 'Dein Freund lädt dich zum Fußballspiel ein. Was antwortest du?', "Ton ami t'invite à un match de football. Que réponds-tu ?", 'Super, ich komme gern mit! Wann und wo treffen wir uns?', 'Super, je viens avec plaisir ! Quand et où nous retrouvons-nous ?', 'komme,gern,treffen,wann'),
    ('Loisirs et sport', 'Du bist am Strand in Kribi. Was machst du dort?', 'Tu es à la plage à Kribi. Que fais-tu là-bas ?', 'Am Strand schwimme ich im Meer, spiele Volleyball und esse frischen Fisch.', 'À la plage, je nage dans la mer, je joue au volley-ball et je mange du poisson frais.', 'strand,schwimme,volleyball,fisch'),
    ('Loisirs et sport', 'Du hast Gäste zu Hause. Welches Spiel schlägst du vor?', 'Tu as des invités chez toi. Quel jeu proposes-tu ?', 'Ich schlage ein Kartenspiel vor, weil alle die Regeln kennen.', 'Je propose un jeu de cartes, parce que tout le monde connaît les règles.', 'kartenspiel,schlage,regeln'),
    ('Loisirs et sport', 'Du bist im Park und siehst einen schönen Vogel. Was machst du?', 'Tu es au parc et tu vois un bel oiseau. Que fais-tu ?', 'Ich nehme mein Handy und mache schnell ein Foto.', 'Je prends mon téléphone et je prends vite une photo.', 'handy,foto,mache'),
    ('Loisirs et sport', 'Beschreibe dein Lieblingsteam.', 'Décris ton équipe préférée.', 'Mein Lieblingsteam ist die Nationalmannschaft von Kamerun. Sie spielt schnell und mutig.', "Mon équipe préférée est l'équipe nationale du Cameroun. Elle joue vite et avec courage.", 'lieblingsteam,nationalmannschaft,kamerun,spielt'),
    ('Loisirs et sport', 'Beschreibe einen perfekten Sonntag.', 'Décris un dimanche parfait.', 'Ein perfekter Sonntag ist für mich ruhig. Ich lese, höre Musik und trinke Kaffee.', "Un dimanche parfait est calme pour moi. Je lis, j'écoute de la musique et je bois du café.", 'sonntag,ruhig,lese,kaffee'),
    ('Loisirs et sport', 'Beschreibe deinen Lieblingsplatz in deiner Stadt.', 'Décris ton endroit préféré dans ta ville.', 'Mein Lieblingsplatz ist ein kleiner Park in Yaoundé. Dort sitze ich gern unter den Bäumen.', "Mon endroit préféré est un petit parc à Yaoundé. J'aime m'y asseoir sous les arbres.", 'lieblingsplatz,park,bäumen,sitze'),
    ('Loisirs et sport', 'Wie bleibst du fit?', 'Comment restes-tu en forme ?', 'Ich bleibe fit, weil ich jeden Morgen laufe und Liegestütze mache.', 'Je reste en forme parce que je cours chaque matin et fais des pompes.', 'fit,laufe,morgen,liegestütze'),
    ('Loisirs et sport', 'Was findest du am Fußball besonders gut?', "Qu'est-ce que tu trouves particulièrement bien dans le football ?", 'Ich finde die Stimmung im Stadion besonders gut.', "Je trouve l'ambiance dans le stade particulièrement bien.", 'stimmung,stadion,finde'),
    ('Loisirs et sport', 'Wie findest du afrikanische Musik?', 'Comment trouves-tu la musique africaine ?', 'Ich finde afrikanische Musik toll, denn der Rhythmus macht gute Laune.', 'Je trouve la musique africaine super, car le rythme met de bonne humeur.', 'musik,toll,rhythmus,finde'),
    ('Loisirs et sport', 'Was findest du besser: Serien oder Filme?', "Qu'est-ce que tu trouves mieux : les séries ou les films ?", 'Ich finde Filme besser, weil sie nicht so lange dauern.', "Je trouve les films mieux, parce qu'ils ne durent pas aussi longtemps.", 'filme,besser,dauern'),
    ('Loisirs et sport', 'Findest du Joggen langweilig oder gesund?', 'Trouves-tu le jogging ennuyeux ou bon pour la santé ?', 'Ich finde Joggen gesund, aber manchmal ein bisschen langweilig.', 'Je trouve le jogging bon pour la santé, mais parfois un peu ennuyeux.', 'joggen,gesund,langweilig'),
    ('Loisirs et sport', 'Was denkst du über Videospiele?', 'Que penses-tu des jeux vidéo ?', 'Ich denke, Videospiele sind lustig, aber man sollte nicht zu lange spielen.', 'Je pense que les jeux vidéo sont amusants, mais on ne devrait pas jouer trop longtemps.', 'videospiele,lustig,spielen'),
    ('Loisirs et sport', 'Warum ist Sport für Kinder wichtig?', 'Pourquoi le sport est-il important pour les enfants ?', 'Sport ist für Kinder wichtig, weil sie dabei stark und gesund werden.', "Le sport est important pour les enfants, parce qu'ils deviennent ainsi forts et en bonne santé.", 'sport,kinder,gesund,wichtig'),
    ('Loisirs et sport', 'Wie findest du Karaoke?', 'Comment trouves-tu le karaoké ?', 'Ich finde Karaoke super, weil ich gern laut singe.', "Je trouve le karaoké super, parce que j'aime chanter fort.", 'karaoke,singe,super'),
    ('Loisirs et sport', 'Was ist für dich ein schönes Hobby?', "Pour toi, qu'est-ce qu'un beau loisir ?", 'Für mich ist Gärtnern ein schönes Hobby, weil man frisches Gemüse bekommt.', "Pour moi, le jardinage est un beau loisir, parce qu'on obtient des légumes frais.", 'hobby,gärtnern,gemüse'),
    ('Loisirs et sport', 'Was hast du letztes Wochenende gemacht?', "Qu'as-tu fait le week-end dernier ?", 'Letztes Wochenende habe ich meine Freunde besucht, und wir haben Fußball angeschaut.', "Le week-end dernier, j'ai rendu visite à mes amis et nous avons regardé du football.", 'wochenende,besucht,angeschaut'),
    ('Loisirs et sport', 'Welchen Film hast du zuletzt gesehen?', 'Quel film as-tu vu en dernier ?', 'Zuletzt habe ich einen lustigen Film aus Nigeria gesehen.', "Dernièrement, j'ai vu un film drôle venant du Nigeria.", 'film,gesehen,zuletzt,nigeria'),
    ('Loisirs et sport', 'Wann hast du zum letzten Mal getanzt?', 'Quand as-tu dansé pour la dernière fois ?', 'Ich habe vor zwei Wochen auf einer Party getanzt, bis spät in die Nacht.', "J'ai dansé il y a deux semaines à une fête, jusque tard dans la nuit.", 'getanzt,party,wochen'),
    ('Loisirs et sport', 'Hast du als Kind viel draußen gespielt?', 'As-tu beaucoup joué dehors quand tu étais enfant ?', 'Ja, als Kind habe ich jeden Tag draußen mit meinen Freunden gespielt.', "Oui, enfant, j'ai joué dehors avec mes amis tous les jours.", 'kind,draußen,gespielt'),
    ('Loisirs et sport', 'Wo bist du im letzten Urlaub gewesen?', 'Où as-tu été lors de tes dernières vacances ?', 'Im letzten Urlaub bin ich in Limbe gewesen und habe das Meer gesehen.', "Lors de mes dernières vacances, j'ai été à Limbé et j'ai vu la mer.", 'urlaub,limbe,meer,gewesen'),
    ('Loisirs et sport', 'Welche Musik hast du als Kind gehört?', 'Quelle musique écoutais-tu quand tu étais enfant ?', 'Als Kind habe ich viel Musik im Radio gehört und mitgesungen.', "Enfant, j'ai beaucoup écouté de la musique à la radio et chanté avec.", 'kind,musik,radio,gehört'),
    ('Loisirs et sport', 'Hast du heute schon Sport gemacht?', "As-tu déjà fait du sport aujourd'hui ?", 'Ja, ich habe heute Morgen eine halbe Stunde gejoggt.', "Oui, ce matin, j'ai fait un jogging d'une demi-heure.", 'gejoggt,heute,morgen,stunde'),
    ('Loisirs et sport', 'Wo hast du dein letztes Foto gemacht?', 'Où as-tu pris ta dernière photo ?', 'Mein letztes Foto habe ich am Fluss gemacht. Es zeigt meine Freundin.', "J'ai pris ma dernière photo au bord de la rivière. Elle montre mon amie.", 'foto,fluss,gemacht'),
    ('Loisirs et sport', 'Mit wem hast du zuletzt Fußball gespielt?', 'Avec qui as-tu joué au football en dernier ?', 'Zuletzt habe ich mit meinen Cousins Fußball gespielt.', "Dernièrement, j'ai joué au football avec mes cousins.", 'fußball,gespielt,cousins'),
    ('Loisirs et sport', 'Hast du schon einmal etwas selbst gebastelt?', 'As-tu déjà fabriqué quelque chose toi-même ?', 'Ja, ich habe für meine Nichte ein Spielzeugauto aus Draht gebastelt.', "Oui, j'ai fabriqué une voiture jouet en fil de fer pour ma nièce.", 'gebastelt,draht,spielzeugauto,nichte'),
    ('Loisirs et sport', 'Wie hast du deinen letzten Sonntag verbracht?', 'Comment as-tu passé ton dernier dimanche ?', 'Meinen letzten Sonntag habe ich ruhig verbracht. Ich habe lange geschlafen und mit meiner Mutter gekocht.', "J'ai passé mon dernier dimanche au calme. J'ai dormi longtemps et cuisiné avec ma mère.", 'sonntag,verbracht,geschlafen,gekocht'),
    ('Loisirs et sport', 'Wann hast du schwimmen gelernt?', 'Quand as-tu appris à nager ?', 'Ich habe mit zehn Jahren im Fluss schwimmen gelernt.', "J'ai appris à nager dans la rivière à dix ans.", 'schwimmen,gelernt,jahren,fluss'),
    ('Loisirs et sport', 'Auf welchem Konzert warst du zuletzt?', 'À quel concert es-tu allé en dernier ?', 'Zuletzt war ich auf einem Konzert von einer Band aus Yaoundé.', "Dernièrement, j'étais à un concert d'un groupe de Yaoundé.", 'konzert,band,zuletzt'),
    ('Loisirs et sport', 'Was hast du zuletzt im Fernsehen gesehen?', "Qu'as-tu regardé en dernier à la télévision ?", 'Gestern habe ich im Fernsehen ein Fußballspiel gesehen.', "Hier, j'ai regardé un match de football à la télévision.", 'fernsehen,fußballspiel,gesehen'),
    ('Loisirs et sport', 'Wo hast du deine Freunde zuletzt getroffen?', 'Où as-tu retrouvé tes amis la dernière fois ?', 'Ich habe meine Freunde zuletzt auf dem Markt getroffen, und wir haben zusammen gegessen.', "J'ai retrouvé mes amis la dernière fois au marché, et nous avons mangé ensemble.", 'freunde,getroffen,markt,gegessen'),
    ('Loisirs et sport', 'Wann hast du zuletzt ein Spiel gewonnen?', 'Quand as-tu gagné un jeu pour la dernière fois ?', 'Letzte Woche habe ich bei einem Brettspiel gegen meinen Bruder gewonnen.', "La semaine dernière, j'ai gagné à un jeu de société contre mon frère.", 'gewonnen,spiel,woche,bruder'),
    ('Loisirs et sport', 'Welche Pläne hast du fürs nächste Wochenende?', 'Quels projets as-tu pour le week-end prochain ?', 'Nächstes Wochenende fahre ich nach Douala und besuche meine Tante.', 'Le week-end prochain, je vais à Douala rendre visite à ma tante.', 'wochenende,fahre,douala,besuche'),
    ('Loisirs et sport', 'Was möchtest du im Urlaub machen?', 'Que veux-tu faire pendant tes vacances ?', 'Im Urlaub möchte ich ans Meer fahren und viel schwimmen.', 'En vacances, je voudrais aller à la mer et beaucoup nager.', 'urlaub,möchte,meer,schwimmen'),
    ('Loisirs et sport', 'Was möchtest du im nächsten Jahr Neues lernen?', "Quelle nouvelle chose voudrais-tu apprendre l'année prochaine ?", 'Im nächsten Jahr möchte ich fotografieren lernen, weil ich schöne Bilder machen will.', "L'année prochaine, je voudrais apprendre la photographie, parce que je veux prendre de belles photos.", 'jahr,fotografieren,lernen,möchte'),
    ('Loisirs et sport', 'Wohin gehst du heute Abend?', 'Où vas-tu ce soir ?', 'Heute Abend gehe ich mit meiner Schwester in ein Café, und wir trinken Saft.', 'Ce soir, je vais dans un café avec ma sœur, et nous buvons du jus.', 'heute,café,schwester,saft'),
    ('Loisirs et sport', 'Was machst du morgen nach der Arbeit?', 'Que fais-tu demain après le travail ?', 'Morgen nach der Arbeit gehe ich ins Fitnessstudio.', 'Demain après le travail, je vais à la salle de sport.', 'morgen,fitnessstudio,arbeit'),
    ('Loisirs et sport', 'Welches Instrument möchtest du gern lernen?', 'Quel instrument voudrais-tu apprendre ?', 'Ich möchte gern Klavier lernen, weil mir der Klang gefällt.', "J'aimerais apprendre le piano, parce que j'aime le son.", 'klavier,lernen,möchte,klang'),
    ('Loisirs et sport', 'Wann willst du das nächste Mal ins Stadion gehen?', 'Quand veux-tu aller au stade la prochaine fois ?', 'Ich will am Sonntag ins Stadion gehen, wenn mein Team spielt.', 'Je veux aller au stade dimanche, quand mon équipe joue.', 'sonntag,stadion,team'),
    ('Loisirs et sport', 'Wie möchtest du deinen nächsten Geburtstag feiern?', 'Comment voudrais-tu fêter ton prochain anniversaire ?', 'Ich möchte meinen Geburtstag mit Freunden feiern, tanzen und Kuchen essen.', 'Je voudrais fêter mon anniversaire avec des amis, danser et manger du gâteau.', 'geburtstag,feiern,tanzen,kuchen'),
    ('Loisirs et sport', 'In welchem Verein möchtest du gern Mitglied werden?', 'Dans quel club aimerais-tu devenir membre ?', 'Ich möchte Mitglied in einem Sportverein werden, denn Sport macht mir Spaß.', "Je voudrais devenir membre d'un club de sport, car le sport me plaît.", 'mitglied,sportverein,möchte'),
    ('Loisirs et sport', 'Wohin fährst du in den nächsten Ferien?', 'Où vas-tu pendant les prochaines vacances ?', 'In den nächsten Ferien fahre ich zu meinen Großeltern ins Dorf.', 'Pendant les prochaines vacances, je vais chez mes grands-parents au village.', 'ferien,fahre,großeltern,dorf'),
    ('Loisirs et sport', 'Wie heißt dein Lieblingssänger oder deine Lieblingssängerin?', "Comment s'appelle ton chanteur ou ta chanteuse préféré(e) ?", 'Meine Lieblingssängerin heißt Charlotte Dipanda. Ich kenne fast alle ihre Lieder.', "Ma chanteuse préférée s'appelle Charlotte Dipanda. Je connais presque toutes ses chansons.", 'lieblingssängerin,heißt,lieder'),
    ('Loisirs et sport', 'Spielst du ein Instrument?', "Joues-tu d'un instrument ?", 'Ja, ich spiele ein bisschen Gitarre, aber noch nicht gut.', 'Oui, je joue un peu de guitare, mais pas encore bien.', 'gitarre,spiele,bisschen'),
    ('Loisirs et sport', 'Wie oft machst du in der Woche Sport?', 'Combien de fois par semaine fais-tu du sport ?', 'Ich mache zweimal in der Woche Sport, am Dienstag und am Freitag.', 'Je fais du sport deux fois par semaine, le mardi et le vendredi.', 'woche,sport,zweimal,dienstag'),
    ('Loisirs et sport', 'Wo kann man in deiner Stadt gut Basketball spielen?', 'Où peut-on bien jouer au basket-ball dans ta ville ?', 'In meiner Stadt kann man auf dem Schulhof gut Basketball spielen.', "Dans ma ville, on peut bien jouer au basket-ball dans la cour de l'école.", 'stadt,basketball,schulhof,spielen'),
    ('Loisirs et sport', 'Welche Sportart ist in Kamerun sehr beliebt?', 'Quel sport est très populaire au Cameroun ?', 'In Kamerun ist Fußball sehr beliebt. Fast alle Kinder spielen auf der Straße.', 'Au Cameroun, le football est très populaire. Presque tous les enfants jouent dans la rue.', 'kamerun,fußball,beliebt,kinder'),
    ('Loisirs et sport', 'Gehst du manchmal ins Fitnessstudio?', 'Vas-tu parfois à la salle de sport ?', 'Nein, ich gehe nicht ins Fitnessstudio. Ich trainiere lieber zu Hause.', "Non, je ne vais pas à la salle de sport. Je préfère m'entraîner à la maison.", 'fitnessstudio,trainiere,hause'),
    ('Loisirs et sport', 'Wie verbringst du die Regenzeit am liebsten?', 'Comment préfères-tu passer la saison des pluies ?', 'In der Regenzeit bleibe ich zu Hause, lese Bücher und schaue Filme.', 'Pendant la saison des pluies, je reste à la maison, je lis des livres et je regarde des films.', 'regenzeit,hause,lese,filme'),
    ('Loisirs et sport', 'Erzähl mir von deinem Lieblingsverein.', 'Parle-moi de ton club préféré.', 'Mein Lieblingsverein ist ein Fußballclub in meiner Stadt. Er spielt jeden Samstag in unserem Stadion, und ich gehe oft mit meinem Vater hin.', "Mon club préféré est un club de football de ma ville. Il joue chaque samedi dans notre stade, et j'y vais souvent avec mon père.", 'lieblingsverein,fußballclub,stadion,spielt'),
    ('Loisirs et sport', 'Erzähl mir von deinem letzten Ausflug.', 'Parle-moi de ta dernière excursion.', 'Letzten Monat habe ich mit Freunden einen Ausflug zu einem Wasserfall gemacht. Wir haben gepicknickt und viele Fotos gemacht.', "Le mois dernier, j'ai fait une excursion à une cascade avec des amis. Nous avons pique-niqué et pris beaucoup de photos.", 'ausflug,wasserfall,fotos'),
    ('Loisirs et sport', 'Erzähl mir von einem Fest in deiner Familie.', "Parle-moi d'une fête dans ta famille.", 'Letztes Jahr haben wir die Hochzeit meiner Cousine gefeiert. Es gab viel Essen, Musik und Tanz.', "L'année dernière, nous avons fêté le mariage de ma cousine. Il y avait beaucoup à manger, de la musique et de la danse.", 'hochzeit,cousine,gefeiert,musik'),
    ('Loisirs et sport', 'Was würdest du machen, wenn du viel Freizeit hättest?', 'Que ferais-tu si tu avais beaucoup de temps libre ?', 'Wenn ich viel Freizeit hätte, würde ich reisen und neue Orte entdecken.', "Si j'avais beaucoup de temps libre, je voyagerais et découvrirais de nouveaux endroits.", 'freizeit,würde,reisen'),
    ('Loisirs et sport', 'Welchen Sport würdest du gern einmal ausprobieren?', 'Quel sport aimerais-tu essayer un jour ?', 'Ich würde gern einmal Tennis ausprobieren, weil ich es noch nie gespielt habe.', "J'aimerais essayer le tennis un jour, parce que je n'y ai encore jamais joué.", 'tennis,ausprobieren,würde,gespielt'),
    ('Loisirs et sport', 'Warum joggen viele Leute in deiner Stadt früh am Morgen?', 'Pourquoi beaucoup de gens font-ils leur jogging tôt le matin dans ta ville ?', 'Ich glaube, am Morgen ist es noch kühl, und die Straßen sind ruhig.', 'Je crois que le matin, il fait encore frais et les rues sont calmes.', 'morgen,kühl,straßen,glaube'),
    ('Loisirs et sport', 'Um wie viel Uhr beginnt deine Lieblingssendung im Fernsehen?', 'À quelle heure commence ton émission préférée à la télévision ?', 'Meine Lieblingssendung beginnt um acht Uhr abends.', 'Mon émission préférée commence à huit heures du soir.', 'lieblingssendung,uhr,abends,beginnt'),
    ('Loisirs et sport', 'Wie viel kostet eine Eintrittskarte für ein Fußballspiel bei dir?', 'Combien coûte un billet pour un match de football chez toi ?', 'Eine Eintrittskarte kostet bei uns ungefähr zweitausend Franc.', 'Chez nous, un billet coûte environ deux mille francs.', 'kostet,eintrittskarte,franc'),
    ('Loisirs et sport', 'Mit wem verbringst du gern deine Freizeit?', 'Avec qui aimes-tu passer ton temps libre ?', 'Ich verbringe meine Freizeit gern mit meinem besten Freund.', "J'aime passer mon temps libre avec mon meilleur ami.", 'verbringe,freund,freizeit'),
    ('Loisirs et sport', 'Wie heißt dein Lieblingsspiel auf dem Handy?', "Comment s'appelle ton jeu préféré sur le téléphone ?", 'Mein Lieblingsspiel auf dem Handy heißt Ludo. Ich spiele es jeden Abend.', "Mon jeu préféré sur le téléphone s'appelle Ludo. J'y joue chaque soir.", 'lieblingsspiel,handy,ludo,spiele'),
    ('Loisirs et sport', 'Fährst du gern Fahrrad?', 'Aimes-tu faire du vélo ?', 'Ja, ich fahre gern Fahrrad, aber in der Stadt ist der Verkehr gefährlich.', "Oui, j'aime faire du vélo, mais en ville la circulation est dangereuse.", 'fahrrad,fahre,verkehr,gefährlich'),
    ('Loisirs et sport', 'Was brauchst du für dein Hobby?', 'De quoi as-tu besoin pour ton loisir ?', 'Für mein Hobby brauche ich nur eine Kamera und ein bisschen Zeit.', "Pour mon loisir, j'ai seulement besoin d'un appareil photo et d'un peu de temps.", 'hobby,brauche,kamera,zeit'),
    ('Loisirs et sport', 'Warum machst du gern Sport?', 'Pourquoi aimes-tu faire du sport ?', 'Ich mache gern Sport, weil ich danach gute Laune habe und besser schlafe.', "J'aime faire du sport, parce qu'ensuite je suis de bonne humeur et je dors mieux.", 'sport,laune,schlafe'),
    ('Loisirs et sport', 'Welche Farben hat das Trikot deines Lieblingsteams?', 'Quelles sont les couleurs du maillot de ton équipe préférée ?', 'Das Trikot meines Lieblingsteams ist grün, rot und gelb.', 'Le maillot de mon équipe préférée est vert, rouge et jaune.', 'trikot,grün,rot,gelb'),
    ('Loisirs et sport', 'Was war dein schönstes Erlebnis beim Sport?', 'Quel a été ton plus beau souvenir en faisant du sport ?', 'Mein schönstes Erlebnis war ein Spiel im Regen. Wir waren nass, aber sehr glücklich.', 'Mon plus beau souvenir est un match sous la pluie. Nous étions trempés, mais très heureux.', 'erlebnis,spiel,regen,glücklich'),
    ('Loisirs et sport', 'Wohin möchtest du am nächsten Feiertag fahren?', 'Où voudrais-tu aller lors du prochain jour férié ?', 'Am nächsten Feiertag möchte ich mit meiner Familie in den Zoo fahren.', 'Lors du prochain jour férié, je voudrais aller au zoo avec ma famille.', 'feiertag,möchte,zoo,familie'),
    ('Loisirs et sport', 'Magst du Picknicks?', 'Aimes-tu les pique-niques ?', 'Ja, ich mag Picknicks. Wir nehmen Brot, Obst und Getränke mit.', "Oui, j'aime les pique-niques. Nous emportons du pain, des fruits et des boissons.", 'picknicks,mag,obst,getränke'),
    ('Loisirs et sport', 'Beschreibe deinen schönsten Tag im Urlaub.', 'Décris ta plus belle journée en vacances.', 'Mein schönster Tag im Urlaub war ein Tag am Meer. Wir haben gebadet, Fisch gegessen und viel gelacht.', 'Ma plus belle journée en vacances était une journée à la mer. Nous nous sommes baignés, avons mangé du poisson et beaucoup ri.', 'urlaub,meer,gebadet,gelacht'),
    ('Loisirs et sport', 'Du hast den Bus zum Stadion verpasst. Was machst du?', 'Tu as raté le bus pour le stade. Que fais-tu ?', 'Ich nehme ein Mototaxi, weil ich das Spiel nicht verpassen möchte.', 'Je prends une moto-taxi, parce que je ne veux pas rater le match.', 'mototaxi,spiel,verpassen'),
    ('Loisirs et sport', 'Du bist auf einer Party. Die Musik gefällt dir nicht. Was sagst du?', 'Tu es à une fête. La musique ne te plaît pas. Que dis-tu ?', 'Entschuldigung, kannst du bitte andere Musik spielen?', "Excuse-moi, peux-tu mettre une autre musique, s'il te plaît ?", 'entschuldigung,andere,musik,bitte'),
    ('Loisirs et sport', 'Was fragst du ihn zu seinen Hobbys?', "Tu fais la connaissance d'un nouveau voisin. Que lui demandes-tu sur ses loisirs ?", 'Ich frage ihn: Welche Hobbys hast du?', 'Je lui demande : quels loisirs as-tu ?', 'frage,hobbys,welche'),
    ('Loisirs et sport', 'Was trinkst du gern, wenn du abends einen Film schaust?', 'Que bois-tu volontiers quand tu regardes un film le soir ?', 'Wenn ich abends einen Film schaue, trinke ich gern Tee mit Milch.', 'Quand je regarde un film le soir, je bois volontiers du thé au lait.', 'film,trinke,tee,milch'),
    ('Voyager et se déplacer', 'Reist du gern?', 'Aimes-tu voyager ?', 'Ja, ich reise sehr gern, weil ich neue Orte sehen möchte.', "Oui, j'aime beaucoup voyager, parce que je veux voir de nouveaux endroits.", 'reise,gern,orte'),
    ('Voyager et se déplacer', 'Wohin möchtest du im Urlaub fahren?', 'Où veux-tu aller en vacances ?', 'Im Urlaub möchte ich nach Spanien fahren, weil ich die Sonne und das Meer liebe.', "En vacances, je voudrais aller en Espagne, parce que j'adore le soleil et la mer.", 'urlaub,fahren,möchte,meer'),
    ('Voyager et se déplacer', 'Wie kommst du zur Arbeit oder zur Schule?', "Comment vas-tu au travail ou à l'école ?", 'Ich fahre jeden Morgen mit dem Bus zur Schule.', "Je vais à l'école en bus chaque matin.", 'bus,fahre,schule'),
    ('Voyager et se déplacer', 'Fährst du lieber mit dem Bus oder mit dem Zug?', 'Préfères-tu voyager en bus ou en train ?', 'Ich fahre lieber mit dem Zug, weil er schneller und bequemer ist.', "Je préfère voyager en train, parce qu'il est plus rapide et plus confortable.", 'zug,lieber,bequemer,schneller'),
    ('Voyager et se déplacer', 'Bist du schon einmal geflogen?', "As-tu déjà pris l'avion ?", 'Ja, ich bin einmal nach Paris geflogen. Der Flug war lang, aber sehr spannend.', "Oui, j'ai pris l'avion une fois pour aller à Paris. Le vol était long, mais très passionnant.", 'geflogen,flug,paris'),
    ('Voyager et se déplacer', 'Nimmst du in Yaoundé oft ein Taxi?', 'Prends-tu souvent un taxi à Yaoundé ?', 'Ja, ich nehme fast jeden Tag ein Taxi, weil es nicht so teuer ist.', "Oui, je prends un taxi presque tous les jours, parce que ce n'est pas si cher.", 'taxi,nehme,teuer'),
    ('Voyager et se déplacer', 'Was kostet eine Fahrt mit dem Mototaxi bei dir?', 'Combien coûte un trajet en moto-taxi chez toi ?', 'Eine kurze Fahrt mit dem Mototaxi kostet ungefähr zweihundert Franc.', 'Un court trajet en moto-taxi coûte environ deux cents francs.', 'mototaxi,kostet,franc'),
    ('Voyager et se déplacer', 'Wie komme ich von deinem Haus zum Markt?', 'Comment aller de chez toi au marché ?', 'Du gehst zuerst geradeaus und biegst dann an der Ampel rechts ab. Der Markt ist neben der Schule.', "Tu vas d'abord tout droit, puis tu tournes à droite au feu. Le marché est à côté de l'école.", 'geradeaus,rechts,markt,ampel'),
    ('Voyager et se déplacer', 'Du suchst den Bahnhof. Was fragst du einen Passanten?', 'Tu cherches la gare. Que demandes-tu à un passant ?', 'Ich frage: Entschuldigung, wo ist der Bahnhof, bitte?', "Je demande : Excusez-moi, où est la gare, s'il vous plaît ?", 'entschuldigung,bahnhof,wo'),
    ('Voyager et se déplacer', 'Du kommst im Hotel an. Was sagst du an der Rezeption?', "Tu arrives à l'hôtel. Que dis-tu à la réception ?", 'Guten Tag, ich habe ein Zimmer für zwei Nächte reserviert.', "Bonjour, j'ai réservé une chambre pour deux nuits.", 'zimmer,reserviert,nächte'),
    ('Voyager et se déplacer', 'Schläfst du im Urlaub lieber im Hotel oder bei Freunden?', "En vacances, préfères-tu dormir à l'hôtel ou chez des amis ?", 'Ich schlafe lieber bei Freunden, weil das billiger ist und mehr Spaß macht.', "Je préfère dormir chez des amis, parce que c'est moins cher et plus amusant.", 'schlafe,freunden,lieber,billiger'),
    ('Voyager et se déplacer', 'Was packst du in deinen Koffer, wenn du verreist?', 'Que mets-tu dans ta valise quand tu pars en voyage ?', 'Ich packe Kleidung, Schuhe und mein Handy in den Koffer.', 'Je mets des vêtements, des chaussures et mon téléphone dans la valise.', 'koffer,packe,kleidung,handy'),
    ('Voyager et se déplacer', 'Hast du einen Rucksack für Reisen?', 'As-tu un sac à dos pour les voyages ?', 'Ja, ich habe einen blauen Rucksack, denn er ist leicht und praktisch.', "Oui, j'ai un sac à dos bleu, car il est léger et pratique.", 'rucksack,habe,leicht,praktisch'),
    ('Voyager et se déplacer', 'Wo kaufst du ein Ticket für eine lange Busfahrt?', 'Où achètes-tu un billet pour un long trajet en bus ?', 'Ich kaufe das Ticket in einer Reiseagentur oder direkt an der Busstation.', "J'achète le billet dans une agence de voyage ou directement à la gare routière.", 'ticket,kaufe,reiseagentur,busstation'),
    ('Voyager et se déplacer', 'Wie viel kostet ein Ticket von Yaoundé nach Douala?', 'Combien coûte un billet de Yaoundé à Douala ?', 'Ein Ticket von Yaoundé nach Douala kostet ungefähr fünftausend Franc.', 'Un billet de Yaoundé à Douala coûte environ cinq mille francs.', 'ticket,kostet,franc,douala'),
    ('Voyager et se déplacer', 'Wie oft fährt der Bus in deiner Stadt?', 'À quelle fréquence le bus passe-t-il dans ta ville ?', 'Der Bus fährt etwa alle fünfzehn Minuten, aber manchmal muss ich länger warten.', 'Le bus passe environ toutes les quinze minutes, mais parfois je dois attendre plus longtemps.', 'bus,fährt,minuten,warten'),
    ('Voyager et se déplacer', 'Welche Stadt möchtest du unbedingt sehen?', 'Quelle ville veux-tu absolument voir ?', 'Ich möchte unbedingt Berlin sehen, weil es eine große und spannende Stadt ist.', "Je veux absolument voir Berlin, parce que c'est une grande ville passionnante.", 'stadt,möchte,sehen,berlin'),
    ('Voyager et se déplacer', 'Welches Land möchtest du einmal besuchen?', 'Quel pays voudrais-tu visiter un jour ?', 'Ich möchte einmal Kanada besuchen, denn dort gibt es viel Natur.', 'Je voudrais visiter le Canada un jour, car il y a beaucoup de nature là-bas.', 'natur,besuchen,möchte,kanada'),
    ('Voyager et se déplacer', 'Aus welchem Land kommst du?', 'De quel pays viens-tu ?', 'Ich komme aus Kamerun und wohne in Yaoundé.', "Je viens du Cameroun et j'habite à Yaoundé.", 'komme,kamerun,wohne'),
    ('Voyager et se déplacer', 'Welche Länder in Afrika kennst du?', "Quels pays d'Afrique connais-tu ?", 'Ich kenne Nigeria, Ghana, den Senegal und natürlich Kamerun.', 'Je connais le Nigeria, le Ghana, le Sénégal et bien sûr le Cameroun.', 'kenne,nigeria,ghana,senegal'),
    ('Voyager et se déplacer', 'Welche Sehenswürdigkeit gefällt dir in deiner Stadt am besten?', 'Quelle curiosité de ta ville te plaît le plus ?', 'Mir gefällt der Berg Mont Fébé am besten, denn von dort sieht man die ganze Stadt.', "Ce que j'aime le plus, c'est le mont Fébé, car de là-haut on voit toute la ville.", 'gefällt,berg,stadt'),
    ('Voyager et se déplacer', 'Welche Sehenswürdigkeit in Deutschland kennst du?', "Quelle curiosité touristique d'Allemagne connais-tu ?", 'Ich kenne das Brandenburger Tor in Berlin. Es ist sehr bekannt.', 'Je connais la porte de Brandebourg à Berlin. Elle est très connue.', 'kenne,brandenburger,berlin'),
    ('Voyager et se déplacer', 'Warst du schon einmal am Meer?', 'As-tu déjà été au bord de la mer ?', 'Ja, ich war letztes Jahr in Limbe am Meer. Der Strand war schwarz und sehr schön.', "Oui, l'an dernier, j'étais à Limbe au bord de la mer. La plage était noire et très belle.", 'meer,strand,war,limbe'),
    ('Voyager et se déplacer', 'Was hast du im letzten Urlaub gemacht?', "Qu'as-tu fait pendant tes dernières vacances ?", 'Im letzten Urlaub habe ich meine Familie besucht und viel geschlafen.', "Pendant mes dernières vacances, j'ai rendu visite à ma famille et beaucoup dormi.", 'urlaub,besucht,familie,geschlafen'),
    ('Voyager et se déplacer', 'Wohin bist du zuletzt gereist?', 'Où as-tu voyagé en dernier ?', 'Zuletzt bin ich nach Bafoussam gereist, um meine Tante zu besuchen.', "Dernièrement, j'ai voyagé à Bafoussam pour rendre visite à ma tante.", 'gereist,bafoussam,tante,besuchen'),
    ('Voyager et se déplacer', 'Mit wem bist du das letzte Mal verreist?', 'Avec qui es-tu parti en voyage la dernière fois ?', 'Letztes Mal bin ich mit meinem Bruder und zwei Freunden verreist.', 'La dernière fois, je suis parti en voyage avec mon frère et deux amis.', 'verreist,bruder,freunden'),
    ('Voyager et se déplacer', 'Wie war deine letzte Reise?', "Comment s'est passé ton dernier voyage ?", 'Meine letzte Reise war toll. Wir haben viele Fotos gemacht und lecker gegessen.', 'Mon dernier voyage était super. Nous avons pris beaucoup de photos et bien mangé.', 'reise,toll,fotos,gegessen'),
    ('Voyager et se déplacer', 'Was hast du von deiner letzten Reise mitgebracht?', "Qu'as-tu rapporté de ton dernier voyage ?", 'Ich habe Mangos und ein kleines Geschenk für meine Mutter mitgebracht.', "J'ai rapporté des mangues et un petit cadeau pour ma mère.", 'mitgebracht,geschenk,mutter,mangos'),
    ('Voyager et se déplacer', 'Hast du auf deiner letzten Reise viele Fotos gemacht?', 'As-tu pris beaucoup de photos pendant ton dernier voyage ?', 'Ja, ich habe viele Fotos mit meinem Handy gemacht.', "Oui, j'ai pris beaucoup de photos avec mon téléphone.", 'fotos,handy,gemacht'),
    ('Voyager et se déplacer', 'Welches Essen hast du im Urlaub probiert?', 'Quel plat as-tu goûté pendant les vacances ?', 'Ich habe frischen Fisch mit Kochbananen probiert. Er war sehr lecker.', "J'ai goûté du poisson frais avec des bananes plantains. Il était très bon.", 'probiert,fisch,kochbananen,lecker'),
    ('Voyager et se déplacer', 'Wohin würdest du gern eine Traumreise machen?', 'Où aimerais-tu faire un voyage de rêve ?', 'Ich würde gern eine Traumreise nach Japan machen, weil ich die Kultur liebe.', "J'aimerais faire un voyage de rêve au Japon, parce que j'adore la culture.", 'traumreise,würde,japan,kultur'),
    ('Voyager et se déplacer', 'Wenn du viel Geld hättest, wohin würdest du reisen?', "Si tu avais beaucoup d'argent, où voyagerais-tu ?", 'Wenn ich viel Geld hätte, würde ich um die ganze Welt reisen.', "Si j'avais beaucoup d'argent, je voyagerais autour du monde entier.", 'geld,hätte,würde,welt,reisen'),
    ('Voyager et se déplacer', 'Mit wem würdest du gern verreisen?', 'Avec qui aimerais-tu partir en voyage ?', 'Ich würde gern mit meiner ganzen Familie verreisen, weil wir viel Spaß zusammen haben.', "J'aimerais partir en voyage avec toute ma famille, parce qu'on s'amuse beaucoup ensemble.", 'würde,verreisen,familie,zusammen'),
    ('Voyager et se déplacer', 'Möchtest du einmal nach Deutschland reisen?', 'Voudrais-tu voyager en Allemagne un jour ?', 'Ja, ich möchte nach Deutschland reisen, um besser Deutsch zu sprechen.', 'Oui, je voudrais voyager en Allemagne pour mieux parler allemand.', 'deutschland,möchte,reisen,deutsch'),
    ('Voyager et se déplacer', 'Was weißt du über das Wetter in Deutschland?', "Que sais-tu du temps qu'il fait en Allemagne ?", 'Ich weiß, dass es im Winter sehr kalt ist und manchmal schneit.', "Je sais qu'en hiver il fait très froid et qu'il neige parfois.", 'weiß,winter,kalt,schneit'),
    ('Voyager et se déplacer', 'Wie kommst du von Kamerun nach Deutschland?', 'Comment vas-tu du Cameroun en Allemagne ?', 'Ich fliege von Douala nach Frankfurt. Der Flug dauert ungefähr acht Stunden.', "Je prends l'avion de Douala à Francfort. Le vol dure environ huit heures.", 'fliege,flug,douala,frankfurt'),
    ('Voyager et se déplacer', 'Brauchst du ein Visum für eine Reise nach Europa?', "As-tu besoin d'un visa pour un voyage en Europe ?", 'Ja, ich brauche ein Visum und muss es vorher bei der Botschaft beantragen.', "Oui, j'ai besoin d'un visa et je dois le demander d'abord à l'ambassade.", 'visum,brauche,botschaft,beantragen'),
    ('Voyager et se déplacer', 'Was brauchst du für eine Reise ins Ausland?', "De quoi as-tu besoin pour un voyage à l'étranger ?", 'Für eine Reise ins Ausland brauche ich einen Reisepass, ein Ticket und etwas Geld.', "Pour un voyage à l'étranger, j'ai besoin d'un passeport, d'un billet et d'un peu d'argent.", 'reisepass,brauche,ausland,ticket,geld'),
    ('Voyager et se déplacer', 'Was musst du an der Grenze zeigen?', 'Que dois-tu montrer à la frontière ?', 'An der Grenze muss ich meinen Pass und manchmal mein Gepäck zeigen.', 'À la frontière, je dois montrer mon passeport et parfois mes bagages.', 'grenze,pass,muss,gepäck'),
    ('Voyager et se déplacer', 'Bist du meistens pünktlich?', 'Es-tu le plus souvent ponctuel ?', 'Ja, ich bin fast immer pünktlich, weil ich früh aufstehe.', 'Oui, je suis presque toujours ponctuel, parce que je me lève tôt.', 'pünktlich,bin,immer,früh'),
    ('Voyager et se déplacer', 'Wie wichtig ist Pünktlichkeit für dich?', 'Quelle importance la ponctualité a-t-elle pour toi ?', 'Pünktlichkeit ist für mich sehr wichtig, denn ich möchte niemanden warten lassen.', 'La ponctualité est très importante pour moi, car je ne veux faire attendre personne.', 'pünktlichkeit,wichtig,warten'),
    ('Voyager et se déplacer', 'Was machst du, wenn dein Bus Verspätung hat?', 'Que fais-tu quand ton bus a du retard ?', 'Wenn mein Bus Verspätung hat, warte ich und schaue auf mein Handy.', "Quand mon bus a du retard, j'attends et je regarde mon téléphone.", 'verspätung,warte,bus,handy'),
    ('Voyager et se déplacer', 'Bist du schon einmal zu spät gekommen?', 'Es-tu déjà arrivé en retard ?', 'Ja, gestern bin ich zu spät zur Schule gekommen, weil es stark geregnet hat.', "Oui, hier je suis arrivé en retard à l'école, parce qu'il a beaucoup plu.", 'spät,gekommen,geregnet'),
    ('Voyager et se déplacer', 'Warum kommen Busse in deiner Stadt oft zu spät?', 'Pourquoi les bus de ta ville arrivent-ils souvent en retard ?', 'Die Busse kommen oft zu spät, weil auf den Straßen viel Verkehr ist.', "Les bus arrivent souvent en retard, parce qu'il y a beaucoup de circulation dans les rues.", 'spät,busse,verkehr,straßen'),
    ('Voyager et se déplacer', 'Wohnst du lieber in einer großen Stadt oder auf dem Land?', 'Préfères-tu habiter dans une grande ville ou à la campagne ?', 'Ich wohne lieber in einer großen Stadt, weil es dort viele Geschäfte gibt.', "Je préfère habiter dans une grande ville, parce qu'il y a beaucoup de magasins.", 'stadt,geschäfte,wohne,lieber'),
    ('Voyager et se déplacer', 'Welche Verkehrsmittel gibt es in deiner Stadt?', 'Quels moyens de transport y a-t-il dans ta ville ?', 'In meiner Stadt gibt es Taxis, Busse und sehr viele Motorräder.', 'Dans ma ville, il y a des taxis, des bus et énormément de motos.', 'motorräder,taxis,busse,gibt'),
    ('Voyager et se déplacer', 'Fährst du oft Fahrrad?', 'Fais-tu souvent du vélo ?', 'Nein, ich fahre selten Fahrrad, weil unsere Straßen sehr steil sind.', 'Non, je fais rarement du vélo, parce que nos routes sont très pentues.', 'fahrrad,fahre,straßen'),
    ('Voyager et se déplacer', 'Wie weit ist dein Haus von der Bushaltestelle entfernt?', "À quelle distance ta maison est-elle de l'arrêt de bus ?", 'Mein Haus ist ungefähr fünf Minuten zu Fuß von der Bushaltestelle entfernt.', "Ma maison est à environ cinq minutes à pied de l'arrêt de bus.", 'haus,bushaltestelle,minuten,fuß'),
    ('Voyager et se déplacer', 'Gehst du gern zu Fuß?', 'Aimes-tu marcher à pied ?', 'Ja, ich gehe gern zu Fuß, denn das ist gesund und kostet nichts.', "Oui, j'aime marcher, car c'est sain et ça ne coûte rien.", 'fuß,gehe,gesund'),
    ('Voyager et se déplacer', 'Bist du schon einmal mit dem Zug gefahren?', 'As-tu déjà pris le train ?', 'Ja, ich bin letztes Jahr mit dem Zug gefahren. Die Fahrt war ruhig und bequem.', "Oui, j'ai pris le train l'an dernier. Le trajet était calme et confortable.", 'zug,gefahren,fahrt'),
    ('Voyager et se déplacer', 'Was gefällt dir am Zugfahren?', "Qu'est-ce qui te plaît dans le voyage en train ?", 'Beim Zugfahren gefällt mir, dass ich entspannt lesen und die Landschaft sehen kann.', "Ce qui me plaît en train, c'est que je peux lire tranquillement et voir le paysage.", 'zugfahren,gefällt,landschaft,lesen'),
    ('Voyager et se déplacer', 'Hast du Angst vor dem Fliegen?', "As-tu peur de prendre l'avion ?", 'Nein, ich habe keine Angst. Ich finde das Fliegen sehr spannend.', "Non, je n'ai pas peur. Je trouve que voler est très passionnant.", 'angst,fliegen,spannend'),
    ('Voyager et se déplacer', 'Was machst du am Flughafen, bevor du ins Flugzeug steigst?', "Que fais-tu à l'aéroport avant de monter dans l'avion ?", 'Zuerst gebe ich meinen Koffer ab, dann gehe ich zur Sicherheitskontrolle.', "D'abord, je dépose ma valise, puis je passe au contrôle de sécurité.", 'koffer,sicherheitskontrolle,gebe'),
    ('Voyager et se déplacer', 'Sitzt du im Flugzeug lieber am Fenster oder am Gang?', "Dans l'avion, préfères-tu t'asseoir côté fenêtre ou côté couloir ?", 'Ich sitze lieber am Fenster, weil ich gern die Wolken sehe.', "Je préfère être assis côté fenêtre, parce que j'aime regarder les nuages.", 'fenster,sitze,lieber,wolken'),
    ('Voyager et se déplacer', 'Du nimmst ein Taxi. Was sagst du dem Fahrer?', 'Tu prends un taxi. Que dis-tu au chauffeur ?', 'Zum Bahnhof, bitte. Wie viel kostet die Fahrt bis dahin?', "À la gare, s'il vous plaît. Combien coûte la course jusque-là ?", 'bahnhof,kostet,fahrt'),
    ('Voyager et se déplacer', 'Wie bezahlst du die Fahrt: bar oder mit Mobile Money?', 'Comment paies-tu le trajet : en espèces ou par Mobile Money ?', 'Ich bezahle meistens bar, aber manchmal auch mit Mobile Money.', 'Je paie le plus souvent en espèces, mais parfois aussi par Mobile Money.', 'bezahle,bar,mobile,money'),
    ('Voyager et se déplacer', 'Was ist dir bei einem Hotelzimmer wichtig?', "Qu'est-ce qui est important pour toi dans une chambre d'hôtel ?", 'Mir ist ein sauberes Bett und ein ruhiges Zimmer wichtig.', 'Un lit propre et une chambre calme sont importants pour moi.', 'zimmer,sauber,bett,ruhig'),
    ('Voyager et se déplacer', 'Hast du schon einmal in einem Hotel übernachtet?', 'As-tu déjà dormi dans un hôtel ?', 'Ja, ich habe einmal in einem kleinen Hotel übernachtet. Das Frühstück war super.', "Oui, j'ai déjà passé une nuit dans un petit hôtel. Le petit-déjeuner était super.", 'hotel,übernachtet,frühstück'),
    ('Voyager et se déplacer', 'Wie lange bleibst du normalerweise im Urlaub?', "Combien de temps restes-tu d'habitude en vacances ?", 'Normalerweise bleibe ich zwei Wochen im Urlaub.', "D'habitude, je reste deux semaines en vacances.", 'bleibe,wochen,urlaub'),
    ('Voyager et se déplacer', 'Reservierst du dein Hotel lieber im Internet oder direkt?', 'Préfères-tu réserver ton hôtel sur Internet ou directement ?', 'Ich reserviere mein Hotel lieber im Internet, weil es dort oft billiger ist.', "Je préfère réserver mon hôtel sur Internet, parce que c'est souvent moins cher.", 'reserviere,hotel,internet,billiger'),
    ('Voyager et se déplacer', 'Wie suchst du Informationen für eine Reise?', 'Comment cherches-tu des informations pour un voyage ?', 'Ich frage meine Freunde nach Tipps und lese Berichte im Internet.', 'Je demande des conseils à mes amis et je lis des articles sur Internet.', 'tipps,freunde,internet,berichte'),
    ('Voyager et se déplacer', 'Planst du eine Reise lange vorher oder fährst du spontan los?', "Planifies-tu un voyage longtemps à l'avance ou pars-tu spontanément ?", 'Ich plane meine Reisen lange vorher, weil ich alles gut organisieren möchte.', "Je planifie mes voyages longtemps à l'avance, parce que je veux bien tout organiser.", 'plane,reise,vorher,organisieren'),
    ('Voyager et se déplacer', 'Was machst du in den nächsten Ferien?', 'Que fais-tu pendant les prochaines vacances ?', 'In den nächsten Ferien besuche ich meine Großeltern im Dorf.', 'Pendant les prochaines vacances, je rends visite à mes grands-parents au village.', 'ferien,besuche,großeltern,dorf'),
    ('Voyager et se déplacer', 'Wohin fährst du am Wochenende?', 'Où vas-tu ce week-end ?', 'Am Wochenende fahre ich mit Freunden zu einem Fluss und wir grillen dort.', 'Ce week-end, je vais avec des amis à une rivière et nous faisons un barbecue là-bas.', 'wochenende,fahre,fluss,grillen'),
    ('Voyager et se déplacer', 'Was möchtest du auf deiner nächsten Reise unbedingt machen?', 'Que veux-tu absolument faire lors de ton prochain voyage ?', 'Auf meiner nächsten Reise möchte ich unbedingt wandern und lokales Essen probieren.', 'Lors de mon prochain voyage, je veux absolument faire de la randonnée et goûter la cuisine locale.', 'nächsten,möchte,wandern,essen'),
    ('Voyager et se déplacer', 'Wann fährst du das nächste Mal in den Urlaub?', 'Quand pars-tu en vacances la prochaine fois ?', 'Das nächste Mal fahre ich im Dezember in den Urlaub.', 'La prochaine fois, je pars en vacances en décembre.', 'dezember,fahre,urlaub'),
    ('Voyager et se déplacer', 'Was findest du an Reisen am schönsten?', "Qu'est-ce que tu trouves le plus beau dans les voyages ?", 'Ich finde am schönsten, dass man neue Menschen und neue Gerichte kennenlernt.', "Ce que je trouve le plus beau, c'est qu'on fait la connaissance de nouvelles personnes et de nouveaux plats.", 'schönsten,menschen,gerichte'),
    ('Voyager et se déplacer', 'Was ist für dich das größte Problem beim Reisen?', 'Quel est pour toi le plus gros problème en voyage ?', 'Das größte Problem beim Reisen ist für mich das schwere Gepäck.', 'Le plus gros problème en voyage, pour moi, ce sont les bagages lourds.', 'problem,gepäck,schwer'),
    ('Voyager et se déplacer', 'Was findest du besser: Strandurlaub oder Städtereise?', 'Que trouves-tu mieux : des vacances à la plage ou un voyage en ville ?', 'Ich finde Strandurlaub besser, weil ich mich gern in der Sonne entspanne.', "Je trouve que les vacances à la plage sont mieux, parce que j'aime me détendre au soleil.", 'strandurlaub,sonne,besser,entspanne'),
    ('Voyager et se déplacer', 'Wie findest du eine lange Busfahrt?', 'Comment trouves-tu un long trajet en bus ?', 'Eine lange Busfahrt finde ich anstrengend, aber ich schlafe oft ein bisschen.', 'Je trouve un long trajet en bus fatigant, mais je dors souvent un peu.', 'busfahrt,anstrengend,lang,schlafe'),
    ('Voyager et se déplacer', 'Was findest du an deiner Heimatstadt besonders schön?', "Qu'est-ce que tu trouves particulièrement beau dans ta ville natale ?", 'An meiner Heimatstadt finde ich die vielen Bäume und die Märkte besonders schön.', 'Dans ma ville natale, je trouve les nombreux arbres et les marchés particulièrement beaux.', 'heimatstadt,schön,märkte,bäume'),
    ('Voyager et se déplacer', 'Findest du es wichtig, ins Ausland zu reisen?', "Trouves-tu important de voyager à l'étranger ?", 'Ja, ich finde es wichtig, weil man dort andere Kulturen sieht und neue Wörter lernt.', "Oui, je trouve ça important, parce qu'on y voit d'autres cultures et on apprend de nouveaux mots.", 'wichtig,kulturen,andere,wörter'),
    ('Voyager et se déplacer', 'Welche Stadt magst du am liebsten und warum?', 'Quelle ville préfères-tu et pourquoi ?', 'Ich mag Douala am liebsten, weil dort immer viel los ist.', "Ma ville préférée est Douala, parce qu'il y a toujours beaucoup d'animation.", 'viel,mag,douala,liebsten'),
    ('Voyager et se déplacer', 'Wie war das Wetter bei deiner letzten Reise?', 'Quel temps faisait-il lors de ton dernier voyage ?', 'Das Wetter war heiß und sonnig, aber am Abend hat es geregnet.', 'Le temps était chaud et ensoleillé, mais le soir il a plu.', 'wetter,heiß,sonnig,geregnet'),
    ('Voyager et se déplacer', 'Du hast deinen Bus verpasst. Was machst du jetzt?', 'Tu as raté ton bus. Que fais-tu maintenant ?', 'Ich warte auf den nächsten Bus und rufe meinen Freund an.', "J'attends le prochain bus et j'appelle mon ami.", 'freund,warte,nächsten,bus'),
    ('Voyager et se déplacer', 'Du bist am Bahnhof. Wie fragst du nach dem Gleis?', 'Tu es à la gare. Comment demandes-tu quel est le quai ?', 'Entschuldigung, von welchem Gleis fährt der Zug nach Köln ab?', 'Excusez-moi, de quel quai part le train pour Cologne ?', 'gleis,zug,fährt,köln'),
    ('Voyager et se déplacer', 'Du hast dich verlaufen. Wen fragst du nach dem Weg?', "Tu t'es perdu. À qui demandes-tu le chemin ?", 'Ich frage eine Verkäuferin und sage: Wie komme ich zum Busbahnhof, bitte?', "Je demande à une vendeuse et je dis : Comment aller à la gare routière, s'il vous plaît ?", 'frage,busbahnhof,verkäuferin,komme'),
    ('Voyager et se déplacer', 'Dein Koffer ist nicht angekommen. Was sagst du am Flughafen?', "Ta valise n'est pas arrivée. Que dis-tu à l'aéroport ?", 'Guten Tag, mein Koffer ist nicht angekommen. Können Sie mir bitte helfen?', "Bonjour, ma valise n'est pas arrivée. Pouvez-vous m'aider, s'il vous plaît ?", 'koffer,angekommen,helfen'),
    ('Voyager et se déplacer', 'Im Hotel ist dein Zimmer zu laut. Was sagst du?', "À l'hôtel, ta chambre est trop bruyante. Que dis-tu ?", 'Guten Abend, mein Zimmer ist leider zu laut. Haben Sie ein anderes Zimmer?', 'Bonsoir, ma chambre est malheureusement trop bruyante. Avez-vous une autre chambre ?', 'zimmer,laut,anderes'),
    ('Voyager et se déplacer', 'Du triffst einen Touristen in deiner Stadt. Was fragst du ihn?', 'Tu rencontres un touriste dans ta ville. Que lui demandes-tu ?', 'Ich frage: Woher kommst du, und wie gefällt dir Yaoundé?', "Je demande : D'où viens-tu et comment trouves-tu Yaoundé ?", 'woher,kommst,gefällt,yaoundé'),
    ('Voyager et se déplacer', 'Ein Freund besucht dich aus Deutschland. Was zeigst du ihm?', "Un ami d'Allemagne te rend visite. Que lui montres-tu ?", 'Ich zeige ihm den großen Markt, den Fluss und natürlich meine Familie.', 'Je lui montre le grand marché, la rivière et bien sûr ma famille.', 'zeige,markt,familie,fluss'),
    ('Voyager et se déplacer', 'Beschreibe deinen Weg von zu Hause zur Schule oder Arbeit.', "Décris ton trajet de chez toi à l'école ou au travail.", 'Ich gehe zuerst zehn Minuten zur Hauptstraße, dann fahre ich mit dem Taxi zur Schule.', "Je marche d'abord dix minutes jusqu'à la route principale, puis je prends le taxi jusqu'à l'école.", 'hauptstraße,gehe,taxi,schule'),
    ('Voyager et se déplacer', 'Beschreibe den Busbahnhof in deiner Stadt.', 'Décris la gare routière de ta ville.', 'Der Busbahnhof ist sehr groß und laut. Dort stehen viele Busse und Händler.', 'La gare routière est très grande et bruyante. Il y a beaucoup de bus et de commerçants.', 'busbahnhof,groß,laut,busse'),
    ('Voyager et se déplacer', 'Beschreibe dein perfektes Urlaubsziel.', 'Décris ta destination de vacances parfaite.', 'Mein perfektes Urlaubsziel hat einen weißen Strand, warmes Wetter und leckeres Essen.', 'Ma destination de vacances parfaite a une plage blanche, un temps chaud et de la bonne nourriture.', 'urlaubsziel,strand,wetter,essen'),
    ('Voyager et se déplacer', 'Erzähl mir von einer schönen Reise.', 'Raconte-moi un beau voyage.', 'Vor zwei Jahren bin ich mit meinem Onkel in den Norden gefahren. Dort war es sehr heiß, aber die Landschaft war toll.', 'Il y a deux ans, je suis allé dans le Nord avec mon oncle. Il y faisait très chaud, mais le paysage était magnifique.', 'onkel,gefahren,landschaft,norden'),
    ('Voyager et se déplacer', 'Erzähl mir von deiner ersten langen Fahrt.', 'Raconte-moi ton premier long trajet.', 'Meine erste lange Fahrt war mit dem Bus zu meiner Oma. Ich war aufgeregt und habe die ganze Zeit Musik gehört.', "Mon premier long trajet s'est fait en bus chez ma grand-mère. J'étais excité et j'ai écouté de la musique tout le temps.", 'fahrt,bus,aufgeregt,musik'),
    ('Voyager et se déplacer', 'Erzähl mir von einem Ort, den du gern wieder besuchen möchtest.', 'Raconte-moi un endroit que tu voudrais bien revisiter.', 'Ich möchte gern wieder zu einem Wasserfall fahren. Dort ist die Natur wunderschön.', 'Je voudrais bien retourner à une cascade. La nature y est magnifique.', 'wasserfall,natur,möchte'),
    ('Voyager et se déplacer', 'Was ist deine schönste Reiseerinnerung?', 'Quel est ton plus beau souvenir de voyage ?', 'Meine schönste Reiseerinnerung ist ein Sonnenuntergang am Meer mit meiner Familie.', 'Mon plus beau souvenir de voyage est un coucher de soleil au bord de la mer avec ma famille.', 'reiseerinnerung,sonnenuntergang,meer'),
    ('Voyager et se déplacer', 'Kaufst du im Urlaub gern Souvenirs?', 'Aimes-tu acheter des souvenirs en vacances ?', 'Ja, ich kaufe gern kleine Souvenirs für meine Freunde und meine Familie.', "Oui, j'aime acheter de petits souvenirs pour mes amis et ma famille.", 'souvenirs,kaufe,freunde'),
    ('Voyager et se déplacer', 'Wie bleibst du im Urlaub mit deiner Familie in Kontakt?', 'Comment restes-tu en contact avec ta famille pendant les vacances ?', 'Ich rufe meine Familie jeden Abend an und schicke Nachrichten über WhatsApp.', "J'appelle ma famille chaque soir et j'envoie des messages par WhatsApp.", 'familie,rufe,schicke,whatsapp'),
    ('Voyager et se déplacer', 'Was brauchst du auf einer langen Busfahrt unbedingt?', 'De quoi as-tu absolument besoin pendant un long trajet en bus ?', 'Auf einer langen Busfahrt brauche ich immer Wasser, Snacks und mein Ladegerät.', "Pendant un long trajet en bus, j'ai toujours besoin d'eau, de snacks et de mon chargeur.", 'busfahrt,wasser,snacks,ladegerät'),
    ('Voyager et se déplacer', 'Wie sicher fühlst du dich im Straßenverkehr?', 'À quel point te sens-tu en sécurité dans la circulation ?', 'Ich fühle mich nicht immer sicher, weil viele Motorräder sehr schnell fahren.', 'Je ne me sens pas toujours en sécurité, parce que beaucoup de motos roulent très vite.', 'sicher,schnell,motorräder,fühle'),
    ('Voyager et se déplacer', 'Hast du einen Führerschein?', 'As-tu un permis de conduire ?', 'Nein, ich habe noch keinen Führerschein, aber ich möchte bald einen machen.', "Non, je n'ai pas encore de permis de conduire, mais je voudrais bientôt le passer.", 'führerschein,habe,möchte'),
    ('Voyager et se déplacer', 'Wer fährt bei euch meistens, wenn ihr verreist?', 'Chez vous, qui conduit le plus souvent quand vous partez en voyage ?', 'Bei uns fährt meistens mein Vater, und ich sitze hinten im Auto.', "Chez nous, c'est le plus souvent mon père qui conduit, et je suis assis à l'arrière de la voiture.", 'fährt,vater,auto,hinten'),
    ('Voyager et se déplacer', 'Wie lange brauchst du bis zum Zentrum deiner Stadt?', 'Combien de temps te faut-il pour aller au centre de ta ville ?', 'Bis zum Zentrum brauche ich mit dem Bus ungefähr eine halbe Stunde.', 'Pour aller au centre, il me faut environ une demi-heure en bus.', 'zentrum,brauche,bus,stunde'),
    ('Voyager et se déplacer', 'Welche Stadt in Kamerun sollte ein Tourist unbedingt besuchen?', 'Quelle ville du Cameroun un touriste devrait-il absolument visiter ?', 'Ein Tourist sollte unbedingt Kribi besuchen, denn der Strand ist dort sehr schön.', 'Un touriste devrait absolument visiter Kribi, car la plage y est très belle.', 'tourist,besuchen,kribi,strand'),
    ('Voyager et se déplacer', 'Was hast du auf deiner letzten Busfahrt gemacht?', "Qu'as-tu fait pendant ton dernier trajet en bus ?", 'Auf meiner letzten Busfahrt habe ich ein Buch gelesen und viel geschlafen.', "Pendant mon dernier trajet en bus, j'ai lu un livre et beaucoup dormi.", 'busfahrt,gelesen,geschlafen,buch'),
    ('Voyager et se déplacer', 'Wen hast du auf einer Reise kennengelernt?', 'Qui as-tu rencontré pendant un voyage ?', 'Im Bus habe ich einen netten Studenten kennengelernt. Wir haben viel gelacht.', "Dans le bus, j'ai rencontré un étudiant sympathique. Nous avons beaucoup ri.", 'kennengelernt,bus,studenten,gelacht'),
    ('Voyager et se déplacer', 'Wie hast du dich auf deine letzte Reise vorbereitet?', "Comment t'es-tu préparé pour ton dernier voyage ?", 'Ich habe meinen Koffer gepackt, ein Ticket gekauft und meine Tante angerufen.', "J'ai fait ma valise, acheté un billet et appelé ma tante.", 'angerufen,koffer,gepackt,ticket'),
    ('Faire les courses', 'Gehst du gern einkaufen?', 'Aimes-tu faire les courses ?', 'Ja, ich gehe gern einkaufen, besonders am Samstag.', "Oui, j'aime faire les courses, surtout le samedi.", 'einkaufen,gern,samstag'),
    ('Faire les courses', 'Wo kaufst du normalerweise Lebensmittel?', 'Où achètes-tu normalement les produits alimentaires ?', 'Ich kaufe Lebensmittel meistens auf dem Markt in meinem Viertel.', "J'achète la plupart du temps mes produits alimentaires au marché de mon quartier.", 'lebensmittel,markt,kaufe'),
    ('Faire les courses', 'Was steht auf deiner Einkaufsliste?', "Qu'y a-t-il sur ta liste de courses ?", 'Auf meiner Einkaufsliste stehen Reis, Tomaten, Zwiebeln und Seife.', 'Sur ma liste de courses, il y a du riz, des tomates, des oignons et du savon.', 'einkaufsliste,reis,tomaten,seife'),
    ('Faire les courses', 'Vergisst du manchmal etwas beim Einkaufen?', 'Oublies-tu parfois quelque chose quand tu fais les courses ?', 'Ja, manchmal vergesse ich das Salz oder die Butter.', "Oui, parfois j'oublie le sel ou le beurre.", 'vergesse,manchmal,salz,butter'),
    ('Faire les courses', 'Wie oft gehst du einkaufen?', 'À quelle fréquence vas-tu faire les courses ?', 'Ich gehe zweimal pro Woche einkaufen, am Mittwoch und am Samstag.', 'Je vais faire les courses deux fois par semaine, le mercredi et le samedi.', 'zweimal,woche,einkaufen'),
    ('Faire les courses', 'Gehst du lieber auf den Markt oder in den Supermarkt?', 'Préfères-tu aller au marché ou au supermarché ?', 'Ich gehe lieber auf den Markt, weil dort alles frisch und billiger ist.', "J'aime mieux aller au marché parce que tout y est frais et moins cher.", 'markt,lieber,frisch,billiger'),
    ('Faire les courses', 'Was hast du gestern gekauft?', "Qu'as-tu acheté hier ?", 'Gestern habe ich Brot, Eier und eine Flasche Öl gekauft.', "Hier, j'ai acheté du pain, des œufs et une bouteille d'huile.", 'gestern,gekauft,brot,eier'),
    ('Faire les courses', 'Wie bezahlst du normalerweise: bar oder mit Karte?', 'Comment paies-tu normalement : en espèces ou par carte ?', 'Ich bezahle meistens bar, weil ich selten eine Karte habe.', "Je paie le plus souvent en espèces parce que j'ai rarement une carte.", 'bar,karte,bezahle'),
    ('Faire les courses', 'Benutzt du Mobile Money zum Bezahlen?', 'Utilises-tu Mobile Money pour payer ?', 'Ja, ich bezahle oft mit Mobile Money, das ist schnell und einfach.', "Oui, je paie souvent avec Mobile Money, c'est rapide et simple.", 'mobile,money,bezahle'),
    ('Faire les courses', 'Kaufst du Kleidung eher auf dem Markt oder im Geschäft?', 'Achètes-tu les vêtements plutôt au marché ou en magasin ?', 'Ich kaufe Kleidung eher im Geschäft, weil ich dort alles anprobieren kann.', "J'achète les vêtements plutôt en magasin parce que je peux tout essayer là-bas.", 'kleidung,geschäft,anprobieren'),
    ('Faire les courses', 'Welche Schuhgröße hast du?', 'Quelle pointure fais-tu ?', 'Ich habe Schuhgröße 42, manchmal brauche ich auch 43.', "Je fais du 42, parfois j'ai aussi besoin du 43.", 'schuhgröße,größe,brauche'),
    ('Faire les courses', 'Welche Kleidergröße trägst du?', 'Quelle taille de vêtements portes-tu ?', 'Ich trage Größe M, bei Hosen manchmal Größe L.', 'Je porte du M, pour les pantalons parfois du L.', 'größe,trage,hosen'),
    ('Faire les courses', 'Welche Farbe magst du bei Kleidung am liebsten?', 'Quelle couleur préfères-tu pour les vêtements ?', 'Ich mag Blau am liebsten, weil diese Farbe gut zu mir passt.', "J'aime le bleu par-dessus tout parce que cette couleur me va bien.", 'farbe,blau,liebsten,passt'),
    ('Faire les courses', 'Trägst du gern bunte Kleidung?', 'Aimes-tu porter des vêtements colorés ?', 'Ja, ich trage gern bunte Hemden, besonders bei Festen.', "Oui, j'aime porter des chemises colorées, surtout pendant les fêtes.", 'bunte,trage,hemden,festen'),
    ('Faire les courses', 'Was hast du dir zuletzt gekauft?', "Qu'est-ce que tu t'es acheté en dernier ?", 'Zuletzt habe ich mir ein Paar neue Schuhe gekauft.', 'Dernièrement, je me suis acheté une paire de chaussures neuves.', 'zuletzt,gekauft,schuhe'),
    ('Faire les courses', 'Wie findest du die Preise in deiner Stadt?', 'Comment trouves-tu les prix dans ta ville ?', 'Ich finde die Preise in Yaoundé ziemlich hoch, besonders für Fleisch.', 'Je trouve les prix à Yaoundé assez élevés, surtout pour la viande.', 'preise,hoch,fleisch'),
    ('Faire les courses', 'Ist das Leben in deiner Stadt teuer?', 'La vie est-elle chère dans ta ville ?', 'Ja, das Leben ist teuer, vor allem die Miete und das Essen.', 'Oui, la vie est chère, surtout le loyer et la nourriture.', 'teuer,miete,essen'),
    ('Faire les courses', 'Sparst du jeden Monat etwas Geld?', "Économises-tu un peu d'argent chaque mois ?", 'Ja, ich spare jeden Monat ein wenig Geld, etwa zehn Prozent meines Lohns.', "Oui, j'économise un peu d'argent chaque mois, environ dix pour cent de mon salaire.", 'spare,monat,geld'),
    ('Faire les courses', 'Wofür sparst du gerade?', 'Pour quoi économises-tu en ce moment ?', 'Ich spare für ein neues Handy, denn mein altes ist kaputt.', "J'économise pour un nouveau téléphone, car l'ancien est cassé.", 'spare,handy,kaputt'),
    ('Faire les courses', 'Was willst du dir von deinem ersten Lohn kaufen?', "Que veux-tu t'acheter avec ton premier salaire ?", 'Von meinem ersten Lohn will ich mir ein Fahrrad kaufen.', "Avec mon premier salaire, je veux m'acheter un vélo.", 'lohn,fahrrad,kaufen'),
    ('Faire les courses', 'Hast du schon einmal online etwas bestellt?', 'As-tu déjà commandé quelque chose en ligne ?', 'Ja, ich habe einmal ein Buch im Internet bestellt.', "Oui, j'ai déjà commandé un livre sur Internet.", 'bestellt,internet,buch'),
    ('Faire les courses', 'Was findest du am Online-Shopping gut oder schlecht?', "Qu'est-ce qui est bien ou mal selon toi dans les achats en ligne ?", 'Gut finde ich, dass es bequem ist. Schlecht ist, dass man die Ware nicht anfassen kann.', "Ce que je trouve bien, c'est que c'est pratique. Ce qui est mal, c'est qu'on ne peut pas toucher la marchandise.", 'bequem,ware,schlecht'),
    ('Faire les courses', 'Hast du schon einmal etwas zurückgegeben?', 'As-tu déjà rendu un article ?', 'Ja, ich habe einmal eine Hose zurückgegeben, weil sie zu klein war.', "Oui, j'ai une fois rendu un pantalon parce qu'il était trop petit.", 'zurückgegeben,hose,klein'),
    ('Faire les courses', 'Wem hast du zuletzt etwas geschenkt?', 'À qui as-tu offert quelque chose dernièrement ?', 'Meinem Bruder habe ich zum Geburtstag ein Trikot geschenkt.', "À mon frère, j'ai offert un maillot pour son anniversaire.", 'geschenkt,bruder,geburtstag'),
    ('Faire les courses', 'Wo kaufst du Geschenke für deine Freunde?', 'Où achètes-tu des cadeaux pour tes amis ?', 'Ich kaufe Geschenke meistens im Einkaufszentrum, weil es dort viel Auswahl gibt.', "J'achète les cadeaux le plus souvent au centre commercial parce qu'il y a beaucoup de choix.", 'geschenke,einkaufszentrum,auswahl'),
    ('Faire les courses', 'Welches ist dein Lieblingsgeschäft?', 'Quel est ton magasin préféré ?', 'Mein Lieblingsgeschäft ist ein kleiner Laden an der Ecke, dort ist alles günstig.', 'Mon magasin préféré est une petite boutique au coin de la rue, tout y est bon marché.', 'lieblingsgeschäft,laden,günstig'),
    ('Faire les courses', 'Warum gehst du so gern in dein Lieblingsgeschäft?', 'Pourquoi aimes-tu tant aller dans ton magasin préféré ?', 'Ich gehe gern dorthin, weil die Verkäuferin sehr freundlich ist.', "J'aime y aller parce que la vendeuse est très aimable.", 'verkäuferin,freundlich,dorthin'),
    ('Faire les courses', 'Gibt es einen Supermarkt in deiner Nähe?', 'Y a-t-il un supermarché près de chez toi ?', 'Ja, fünf Minuten von meinem Haus entfernt gibt es einen großen Supermarkt.', 'Oui, à cinq minutes de chez moi il y a un grand supermarché.', 'supermarkt,minuten,haus'),
    ('Faire les courses', 'Was kaufst du im Supermarkt am häufigsten?', "Qu'achètes-tu le plus souvent au supermarché ?", 'Im Supermarkt kaufe ich am häufigsten Milch, Nudeln und Wasser.', "Au supermarché, j'achète le plus souvent du lait, des pâtes et de l'eau.", 'supermarkt,milch,nudeln,wasser'),
    ('Faire les courses', 'Wie viel Geld gibst du pro Woche für Essen aus?', "Combien d'argent dépenses-tu par semaine pour la nourriture ?", 'Für Essen gebe ich pro Woche ungefähr 15.000 Franc aus.', 'Pour la nourriture, je dépense environ 15 000 francs par semaine.', 'essen,gebe,woche,franc'),
    ('Faire les courses', 'Fährst du mit dem Taxi-Moto zum Markt?', 'Vas-tu au marché en moto-taxi ?', 'Ja, ich fahre mit dem Taxi-Moto zum Markt, weil es schneller geht als mit dem Bus.', "Oui, je vais au marché en moto-taxi parce que c'est plus rapide qu'en bus.", 'taxi-moto,markt,fahre'),
    ('Faire les courses', 'Verhandelst du auf dem Markt über den Preis?', 'Marchandes-tu le prix au marché ?', 'Ja, ich verhandle immer, denn der erste Preis ist oft zu hoch.', 'Oui, je marchande toujours, car le premier prix est souvent trop élevé.', 'verhandle,preis,hoch'),
    ('Faire les courses', 'Wie fragst du auf dem Markt nach dem Preis?', 'Comment demandes-tu le prix au marché ?', 'Ich frage: „Entschuldigung, wie viel ist das?“', "Je demande : « Excusez-moi, c'est combien ? »", 'frage,entschuldigung,viel'),
    ('Faire les courses', 'Kannst du gut handeln?', 'Sais-tu bien marchander ?', 'Ja, ich kann ziemlich gut handeln, aber meine Mutter kann es noch besser.', 'Oui, je sais plutôt bien marchander, mais ma mère le fait encore mieux.', 'handeln,kann,mutter'),
    ('Faire les courses', 'Du kaufst Tomaten auf dem Markt. Was sagst du zur Verkäuferin?', 'Tu achètes des tomates au marché. Que dis-tu à la vendeuse ?', 'Ich sage: „Guten Tag, ich möchte ein Kilo Tomaten, bitte. Was kostet das?“', "Je dis : « Bonjour, je voudrais un kilo de tomates, s'il vous plaît. Combien ça coûte ? »", 'kilo,tomaten,möchte,kostet'),
    ('Faire les courses', 'Der Verkäufer nennt 5.000 Franc. Es ist zu teuer. Was sagst du?', "Le vendeur annonce 5 000 francs. C'est trop cher. Que dis-tu ?", 'Ich sage: „Das ist mir zu teuer. Ich gebe Ihnen 3.000 Franc.“', "Je dis : « C'est trop cher pour moi. Je vous donne 3 000 francs. »", 'teuer,franc,gebe'),
    ('Faire les courses', 'Welche Früchte hast du am Sonntag auf dem Markt gekauft?', 'Quels fruits as-tu achetés dimanche au marché ?', 'Am Sonntag habe ich Mangos, Bananen und Ananas gekauft.', "Dimanche, j'ai acheté des mangues, des bananes et des ananas.", 'mangos,bananen,ananas,gekauft'),
    ('Faire les courses', 'Was brauchst du, um Ndolé zu kochen?', 'De quoi as-tu besoin pour cuisiner du ndolé ?', 'Für Ndolé brauche ich Ndolé-Blätter, Erdnüsse, Knoblauch und Fleisch.', "Pour le ndolé, j'ai besoin de feuilles de ndolé, d'arachides, d'ail et de viande.", 'ndolé,erdnüsse,brauche'),
    ('Faire les courses', 'Welches Gemüse hast du diese Woche gekauft?', 'Quels légumes as-tu achetés cette semaine ?', 'Diese Woche habe ich Karotten, Salat und Okra gekauft.', "Cette semaine, j'ai acheté des carottes, de la salade et du gombo.", 'salat,karotten,okra,gekauft'),
    ('Faire les courses', 'Bringst du eine Tasche zum Einkaufen mit?', 'Apportes-tu un sac pour faire les courses ?', 'Ja, ich bringe immer eine Stofftasche mit, damit ich keine Plastiktüte brauche.', "Oui, j'apporte toujours un sac en tissu pour ne pas avoir besoin de sac plastique.", 'tasche,stofftasche,bringe'),
    ('Faire les courses', 'Welche Tasche trägst du jeden Tag?', 'Quel sac portes-tu tous les jours ?', 'Ich trage jeden Tag einen kleinen schwarzen Rucksack.', 'Je porte tous les jours un petit sac à dos noir.', 'rucksack,trage,schwarzen'),
    ('Faire les courses', 'Beschreibe deine Lieblingstasche.', 'Décris ton sac préféré.', 'Meine Lieblingstasche ist braun und hat drei Fächer. Sie ist aus Leder.', 'Mon sac préféré est marron et a trois compartiments. Il est en cuir.', 'lieblingstasche,braun,leder'),
    ('Faire les courses', 'Hast du ein Smartphone?', 'As-tu un smartphone ?', 'Ja, ich habe ein Smartphone von Samsung, es ist zwei Jahre alt.', "Oui, j'ai un smartphone Samsung, il a deux ans.", 'smartphone,samsung,jahre'),
    ('Faire les courses', 'Wo hast du dein Handy gekauft?', 'Où as-tu acheté ton téléphone ?', 'Ich habe mein Handy in einem kleinen Geschäft in Douala gekauft.', "J'ai acheté mon téléphone dans une petite boutique à Douala.", 'handy,gekauft,douala'),
    ('Faire les courses', 'Worauf achtest du, wenn du ein Handy kaufst?', 'À quoi fais-tu attention quand tu achètes un téléphone ?', 'Ich achte auf den Preis, auf die Kamera und darauf, wie lange der Akku hält.', "Je fais attention au prix, à l'appareil photo et à la durée de la batterie.", 'preis,kamera,akku,achte'),
    ('Faire les courses', 'Welche Marke findest du bei Handys am besten?', 'Quelle marque trouves-tu la meilleure pour les téléphones ?', 'Ich finde Tecno am besten, weil die Handys günstig und robust sind.', 'Je trouve que Tecno est la meilleure parce que les téléphones sont bon marché et solides.', 'handys,tecno,günstig,robust'),
    ('Faire les courses', 'Wie viel Guthaben kaufst du pro Monat für dein Handy?', 'Combien de crédit achètes-tu par mois pour ton téléphone ?', 'Ich kaufe jeden Monat Guthaben für 5.000 Franc, das reicht für Anrufe und Internet.', "J'achète chaque mois du crédit pour 5 000 francs, ça suffit pour les appels et Internet.", 'guthaben,monat,franc,internet'),
    ('Faire les courses', 'Probierst du Kleidung an, bevor du sie kaufst?', 'Essaies-tu les vêtements avant de les acheter ?', 'Ja, ich probiere immer alles an, denn die Größe ist nicht überall gleich.', "Oui, j'essaie toujours tout, car la taille n'est pas la même partout.", 'probiere,größe,gleich'),
    ('Faire les courses', 'Was trägst du heute?', "Que portes-tu aujourd'hui ?", 'Heute trage ich eine blaue Jeans, ein weißes T-Shirt und Sneaker.', "Aujourd'hui, je porte un jean bleu, un T-shirt blanc et des baskets.", 'trage,jeans,t-shirt,sneaker'),
    ('Faire les courses', 'Was ziehst du in der Regenzeit an?', 'Que mets-tu pendant la saison des pluies ?', 'In der Regenzeit ziehe ich eine Regenjacke an und nehme einen Schirm mit.', 'Pendant la saison des pluies, je mets un imperméable et je prends un parapluie.', 'regenzeit,regenjacke,schirm'),
    ('Faire les courses', 'Wie viele Paar Schuhe hast du?', 'Combien de paires de chaussures as-tu ?', 'Ich habe ungefähr sechs Paar Schuhe, aber ich trage meistens nur zwei davon.', "J'ai environ six paires de chaussures, mais je n'en porte le plus souvent que deux.", 'paar,schuhe,sechs'),
    ('Faire les courses', 'Trägst du lieber Sandalen oder Turnschuhe?', 'Portes-tu plutôt des sandales ou des baskets ?', 'Ich trage lieber Sandalen, weil es in Kamerun oft sehr heiß ist.', "Je préfère porter des sandales parce qu'il fait souvent très chaud au Cameroun.", 'sandalen,lieber,heiß'),
    ('Faire les courses', 'Wie viel darf ein Paar gute Schuhe kosten?', 'Combien peut coûter une bonne paire de chaussures ?', 'Für mich darf ein Paar gute Schuhe höchstens 20.000 Franc kosten.', 'Pour moi, une bonne paire de chaussures peut coûter au maximum 20 000 francs.', 'schuhe,höchstens,franc,kosten'),
    ('Faire les courses', 'Wie findest du Sonderangebote im Supermarkt?', 'Que penses-tu des promotions au supermarché ?', 'Ich finde Sonderangebote gut, aber man kauft dann manchmal zu viel.', 'Je trouve les promotions bien, mais on achète alors parfois trop.', 'sonderangebote,gut,kauft'),
    ('Faire les courses', 'Was kaufst du, wenn es einen Rabatt gibt?', "Qu'achètes-tu quand il y a une réduction ?", 'Wenn es Rabatt gibt, kaufe ich Seife und Reis in großen Mengen.', "Quand il y a une réduction, j'achète du savon et du riz en grandes quantités.", 'rabatt,seife,reis,kaufe'),
    ('Faire les courses', 'Was hältst du von Kundenkarten?', 'Que penses-tu des cartes de fidélité ?', 'Ich halte Kundenkarten für gut, weil man Punkte sammelt und Geld sparen kann.', "Je trouve les cartes de fidélité bien parce qu'on cumule des points et qu'on peut économiser de l'argent.", 'kundenkarten,punkte,sparen'),
    ('Faire les courses', 'Was machst du, wenn du kein Geld mehr hast?', "Que fais-tu quand tu n'as plus d'argent ?", 'Wenn ich kein Geld mehr habe, frage ich meine Familie oder arbeite mehr.', "Quand je n'ai plus d'argent, je demande à ma famille ou je travaille plus.", 'geld,familie,arbeite'),
    ('Faire les courses', 'Gibst du lieber Geld aus oder sparst du lieber?', "Préfères-tu dépenser de l'argent ou en économiser ?", 'Ich spare lieber, aber manchmal kaufe ich mir etwas Schönes.', "Je préfère économiser, mais parfois je m'achète quelque chose de beau.", 'spare,lieber,kaufe'),
    ('Faire les courses', 'Wie viel Geld hast du letzten Monat ausgegeben?', "Combien d'argent as-tu dépensé le mois dernier ?", 'Letzten Monat habe ich ungefähr 80.000 Franc ausgegeben.', "Le mois dernier, j'ai dépensé environ 80 000 francs.", 'letzten,monat,ausgegeben,franc'),
    ('Faire les courses', 'Hast du heute schon etwas gekauft?', "As-tu déjà acheté quelque chose aujourd'hui ?", 'Ja, heute Morgen habe ich Avocados und Wasser gekauft.', "Oui, ce matin j'ai acheté des avocats et de l'eau.", 'heute,avocados,wasser,gekauft'),
    ('Faire les courses', 'Was hast du letzte Woche auf dem Markt gekauft?', "Qu'as-tu acheté au marché la semaine dernière ?", 'Letzte Woche habe ich auf dem Markt Fisch und Kochbananen gekauft.', "La semaine dernière, j'ai acheté du poisson et des plantains au marché.", 'markt,fisch,kochbananen,gekauft'),
    ('Faire les courses', 'Mit wem bist du zuletzt einkaufen gegangen?', 'Avec qui es-tu allé faire les courses dernièrement ?', 'Ich bin mit meiner Schwester einkaufen gegangen, wir haben viel gelacht.', 'Je suis allé faire les courses avec ma sœur, nous avons beaucoup ri.', 'schwester,einkaufen,gegangen'),
    ('Faire les courses', 'Wer kauft bei dir zu Hause das Essen ein?', 'Qui fait les courses de nourriture chez toi ?', 'Meistens kauft meine Mutter das Essen ein, aber manchmal helfe ich ihr.', "La plupart du temps, c'est ma mère qui fait les courses, mais parfois je l'aide.", 'mutter,kauft,essen,helfe'),
    ('Faire les courses', 'Wie bist du das letzte Mal zum Markt gekommen?', 'Comment es-tu venu au marché la dernière fois ?', 'Ich bin zu Fuß gegangen, es hat nur zehn Minuten gedauert.', "Je suis venu à pied, cela n'a pris que dix minutes.", 'fuß,gegangen,minuten'),
    ('Faire les courses', 'Wann gehst du am liebsten auf den Markt?', 'Quand préfères-tu aller au marché ?', 'Am liebsten gehe ich früh am Morgen, dann ist alles frisch.', 'Je préfère y aller tôt le matin, alors tout est frais.', 'morgen,früh,frisch'),
    ('Faire les courses', 'Wie sieht der Markt in deiner Stadt aus?', 'À quoi ressemble le marché de ta ville ?', 'Der Markt ist groß und laut, und es gibt viele Stände mit Obst und Stoffen.', "Le marché est grand et bruyant, et il y a beaucoup d'étals avec des fruits et des tissus.", 'markt,stände,groß,obst'),
    ('Faire les courses', 'Woher bekommst du schöne Stoffe für ein Fest?', 'Où trouves-tu de beaux tissus pour une fête ?', 'Schöne Stoffe bekomme ich auf dem Markt, und mein Schneider näht dann ein Kleid oder ein Hemd.', 'Je trouve de beaux tissus au marché, et mon couturier me coud ensuite une robe ou une chemise.', 'stoffe,schneider,markt'),
    ('Faire les courses', 'Zählst du dein Wechselgeld nach?', 'Comptes-tu ta monnaie ?', 'Ja, ich zähle das Wechselgeld immer nach, damit alles stimmt.', 'Oui, je recompte toujours la monnaie pour que tout soit correct.', 'wechselgeld,zähle,stimmt'),
    ('Faire les courses', 'Was machst du, wenn der Verkäufer kein Wechselgeld hat?', "Que fais-tu quand le vendeur n'a pas de monnaie ?", 'Dann bezahle ich mit Mobile Money oder suche einen anderen Stand.', 'Alors je paie avec Mobile Money ou je cherche un autre étal.', 'bezahle,mobile,stand,suche'),
    ('Faire les courses', 'Bekommst du immer eine Quittung, wenn du bezahlst?', 'Reçois-tu toujours un reçu quand tu paies ?', 'Nein, auf dem Markt bekomme ich meistens keine Quittung.', 'Non, au marché je ne reçois le plus souvent pas de reçu.', 'quittung,markt,keine'),
    ('Faire les courses', 'Würdest du gern in Deutschland einkaufen?', 'Aimerais-tu faire des courses en Allemagne ?', 'Ja, ich würde gern in Deutschland einkaufen, denn ich möchte deutsche Schokolade probieren.', "Oui, j'aimerais faire des courses en Allemagne car je voudrais goûter du chocolat allemand.", 'deutschland,einkaufen,schokolade'),
    ('Faire les courses', 'Was würdest du mit 100.000 Franc kaufen?', "Qu'achèterais-tu avec 100 000 francs ?", 'Mit 100.000 Franc würde ich Kleidung für meine Familie kaufen.', "Avec 100 000 francs, j'achèterais des vêtements pour ma famille.", 'franc,würde,kleidung,familie'),
    ('Faire les courses', 'Du hast 10.000 Franc. Was kaufst du für das Abendessen?', "Tu as 10 000 francs. Qu'achètes-tu pour le dîner ?", 'Ich kaufe Kartoffeln und Hähnchen, das reicht für die ganze Familie.', "J'achète des pommes de terre et du poulet, ça suffit pour toute la famille.", 'kartoffeln,hähnchen,familie'),
    ('Faire les courses', 'Was musst du morgen noch einkaufen?', 'Que dois-tu encore acheter demain ?', 'Morgen muss ich noch Zucker, Kaffee und Zahnpasta einkaufen.', 'Demain, je dois encore acheter du sucre, du café et du dentifrice.', 'morgen,muss,zucker,zahnpasta'),
    ('Faire les courses', 'Welches Kleidungsstück trägst du am liebsten?', 'Quel vêtement portes-tu le plus volontiers ?', 'Mein weißes Hemd trage ich am liebsten, weil es schön und leicht ist.', "Ma chemise blanche est celle que je porte le plus volontiers parce qu'elle est belle et légère.", 'weißes,hemd,leicht'),
    ('Faire les courses', 'Du bist im Geschäft. Die Hose ist zu groß. Was sagst du?', 'Tu es dans le magasin. Le pantalon est trop grand. Que dis-tu ?', 'Ich sage: „Entschuldigung, haben Sie diese Hose auch in einer kleineren Größe?“', 'Je dis : « Excusez-moi, avez-vous ce pantalon aussi dans une taille plus petite ? »', 'hose,größe,kleineren,haben'),
    ('Faire les courses', 'Das T-Shirt gefällt dir, aber die Farbe nicht. Was fragst du?', 'Le T-shirt te plaît, mais pas la couleur. Que demandes-tu ?', 'Ich frage: „Haben Sie das T-Shirt auch in Rot oder in Grün?“', 'Je demande : « Avez-vous ce T-shirt aussi en rouge ou en vert ? »', 't-shirt,rot,grün,haben'),
    ('Faire les courses', 'Was sagst du an der Kasse, wenn du mit Karte zahlen willst?', 'Que dis-tu à la caisse quand tu veux payer par carte ?', 'Ich sage: „Kann ich bitte mit Karte zahlen?“', "Je dis : « Puis-je payer par carte, s'il vous plaît ? »", 'karte,zahlen,bitte'),
    ('Faire les courses', 'Wann zahlst du mit dem Handy statt mit Bargeld?', "Quand paies-tu avec le téléphone plutôt qu'en espèces ?", 'Ich zahle mit dem Handy, wenn ich kein Bargeld dabei habe oder wenn der Betrag groß ist.', "Je paie avec le téléphone quand je n'ai pas d'espèces sur moi ou quand le montant est élevé.", 'handy,bargeld,zahle'),
    ('Faire les courses', 'Hast du schon einmal Geld überwiesen?', "As-tu déjà envoyé de l'argent par virement ?", 'Ja, ich habe meiner Schwester Geld überwiesen, als sie in Douala studiert hat.', "Oui, j'ai envoyé de l'argent à ma sœur quand elle étudiait à Douala.", 'geld,überwiesen,schwester'),
    ('Faire les courses', 'Wie schickst du Geld an deine Familie?', "Comment envoies-tu de l'argent à ta famille ?", 'Ich schicke das Geld über eine App, das geht in wenigen Sekunden.', "J'envoie l'argent par une application, ça prend quelques secondes.", 'geld,schicke,app'),
    ('Faire les courses', 'Kaufst du lieber neue oder gebrauchte Sachen?', "Préfères-tu acheter des choses neuves ou d'occasion ?", 'Ich kaufe lieber gebrauchte Sachen, denn sie sind viel billiger.', "Je préfère acheter des choses d'occasion car elles sont beaucoup moins chères.", 'gebrauchte,billiger,lieber'),
    ('Faire les courses', 'Wie findest du Einkaufszentren?', 'Que penses-tu des centres commerciaux ?', 'Ich finde Einkaufszentren praktisch, aber dort ist es mir oft zu voll.', 'Je trouve les centres commerciaux pratiques, mais il y a souvent trop de monde pour moi.', 'einkaufszentren,praktisch,voll'),
    ('Faire les courses', 'Was hat dich beim letzten Einkauf geärgert?', "Qu'est-ce qui t'a énervé lors de tes dernières courses ?", 'Beim letzten Einkauf hat mich die lange Schlange an der Kasse geärgert.', "Lors de mes dernières courses, la longue file d'attente à la caisse m'a énervé.", 'geärgert,kasse,schlange'),
    ('Faire les courses', 'Was war dein größter Fehlkauf?', 'Quel a été ton pire achat raté ?', 'Mein größter Fehlkauf waren billige Kopfhörer, sie waren nach einer Woche kaputt.', "Mon pire achat raté, ce sont des écouteurs bon marché, ils étaient cassés au bout d'une semaine.", 'fehlkauf,kopfhörer,kaputt'),
    ('Faire les courses', 'Wo möchtest du dein nächstes Handy kaufen?', 'Où voudrais-tu acheter ton prochain téléphone ?', 'Ich möchte mein nächstes Handy online bestellen, weil es dort billiger ist.', "Je voudrais commander mon prochain téléphone en ligne parce que c'est moins cher là-bas.", 'handy,online,bestellen'),
    ('Faire les courses', 'Bei welcher Bäckerei kaufst du dein Brot?', 'Dans quelle boulangerie achètes-tu ton pain ?', 'Ich kaufe mein Brot bei der Bäckerei neben meinem Haus, dort ist es noch warm.', "J'achète mon pain à la boulangerie à côté de chez moi, il y est encore chaud.", 'brot,bäckerei,warm'),
    ('Faire les courses', 'Erzähl mir von deinem letzten Einkauf im Supermarkt.', 'Raconte-moi ta dernière course au supermarché.', 'Ich war am Sonntag im Supermarkt und habe Joghurt, Käse und Saft gekauft. An der Kasse habe ich lange gewartet.', "J'étais au supermarché dimanche et j'ai acheté du yaourt, du fromage et du jus. J'ai longtemps attendu à la caisse.", 'supermarkt,joghurt,gekauft,kasse'),
    ('Faire les courses', 'Kaufst du manchmal etwas, das du nicht brauchst?', "Achètes-tu parfois quelque chose dont tu n'as pas besoin ?", 'Ja, manchmal kaufe ich Süßigkeiten, aber ich brauche sie eigentlich nicht.', "Oui, parfois j'achète des bonbons, mais en fait je n'en ai pas besoin.", 'süßigkeiten,brauche,manchmal'),
    ('Faire les courses', 'Was kostet eine Flasche Wasser bei dir?', "Combien coûte une bouteille d'eau chez toi ?", 'Eine Flasche Wasser kostet bei uns etwa 500 Franc.', "Une bouteille d'eau coûte chez nous environ 500 francs.", 'flasche,wasser,kostet,franc'),
    ('Faire les courses', 'Was möchtest du deiner Familie zum Jahresende schenken?', "Que voudrais-tu offrir à ta famille pour la fin de l'année ?", 'Ich möchte meiner Familie neue Kleider und Schuhe schenken.', 'Je voudrais offrir à ma famille des vêtements et des chaussures neufs.', 'möchte,familie,schenken'),
    ('Faire les courses', 'Gehst du lieber am Wochenende oder unter der Woche einkaufen?', 'Préfères-tu faire les courses le week-end ou en semaine ?', 'Ich gehe lieber unter der Woche einkaufen, dann sind weniger Leute da.', 'Je préfère faire les courses en semaine, il y a alors moins de monde.', 'woche,lieber,leute'),
    ('Faire les courses', 'Wann bist du zuletzt auf dem Markt gewesen?', 'Quand es-tu allé au marché pour la dernière fois ?', 'Ich war vor drei Tagen auf dem Markt und habe Orangen gekauft.', "J'y étais il y a trois jours et j'ai acheté des oranges.", 'markt,war,tagen,orangen'),
    ('Faire les courses', 'Wie heißt die Währung in Kamerun?', "Comment s'appelle la monnaie au Cameroun ?", 'Die Währung in Kamerun heißt Franc CFA, in Deutschland bezahlt man mit Euro.', "La monnaie au Cameroun s'appelle franc CFA, en Allemagne on paie en euros.", 'währung,franc,euro'),
    ('Faire les courses', 'Was isst du gern, wenn du auf dem Markt bist?', 'Que manges-tu volontiers quand tu es au marché ?', 'Auf dem Markt esse ich gern gegrillten Mais und trinke einen kalten Saft.', "Au marché, j'aime manger du maïs grillé et boire un jus frais.", 'mais,esse,saft'),
    ('Faire les courses', 'Wem hast du zuletzt beim Einkaufen geholfen?', 'Qui as-tu aidé dernièrement pour les courses ?', 'Ich habe meiner Großmutter geholfen, sie kann die schweren Taschen nicht tragen.', "J'ai aidé ma grand-mère, elle ne peut pas porter les sacs lourds.", 'geholfen,großmutter,taschen'),
    ('Faire les courses', 'Du machst am Samstag eine Party. Was kaufst du ein?', "Tu organises une fête samedi. Qu'achètes-tu ?", 'Ich kaufe Getränke, einen Kuchen, Chips und Luftballons ein.', "J'achète des boissons, un gâteau, des chips et des ballons.", 'chips,getränke,kuchen,luftballons'),
    ('Faire les courses', 'Welche Geschäfte gibt es in deiner Straße?', 'Quels magasins y a-t-il dans ta rue ?', 'In meiner Straße gibt es einen Friseur, eine Apotheke und einen kleinen Laden.', 'Dans ma rue, il y a un coiffeur, une pharmacie et une petite boutique.', 'straße,friseur,apotheke,laden'),
    ('Santé et corps', 'Wie geht es dir heute?', "Comment vas-tu aujourd'hui ?", 'Mir geht es heute gut, aber ich bin ein bisschen müde.', "Aujourd'hui, je vais bien, mais je suis un peu fatigué.", 'gut,müde,geht'),
    ('Santé et corps', 'Bist du heute müde?', "Es-tu fatigué aujourd'hui ?", 'Ja, ich bin heute ein bisschen müde und möchte früh ins Bett gehen.', "Oui, je suis un peu fatigué aujourd'hui et je voudrais aller me coucher tôt.", 'müde,bett,früh'),
    ('Santé et corps', 'Wie viele Stunden schläfst du pro Nacht?', "Combien d'heures dors-tu par nuit ?", 'Ich schlafe jede Nacht ungefähr sieben Stunden.', 'Je dors environ sept heures chaque nuit.', 'stunden,schlafe,nacht'),
    ('Santé et corps', 'Wann gehst du normalerweise ins Bett?', 'Quand vas-tu normalement au lit ?', 'Normalerweise gehe ich gegen zehn Uhr ins Bett.', 'Normalement, je vais au lit vers dix heures.', 'bett,uhr,gehe'),
    ('Santé et corps', 'Wann stehst du morgen auf?', 'À quelle heure te lèves-tu demain ?', 'Morgen stehe ich um halb sieben auf, weil ich früh arbeiten muss.', 'Demain, je me lève à six heures et demie parce que je dois travailler tôt.', 'morgen,halb,sieben'),
    ('Santé et corps', 'Hast du oft Kopfschmerzen?', 'As-tu souvent mal à la tête ?', 'Ja, ich habe oft Kopfschmerzen, besonders wenn ich lange am Handy bin.', "Oui, j'ai souvent mal à la tête, surtout quand je reste longtemps sur mon téléphone.", 'kopfschmerzen,oft,handy'),
    ('Santé et corps', 'Was machst du, wenn du Kopfschmerzen hast?', 'Que fais-tu quand tu as mal à la tête ?', 'Wenn ich Kopfschmerzen habe, trinke ich viel Wasser und lege mich hin.', "Quand j'ai mal à la tête, je bois beaucoup d'eau et je m'allonge.", 'kopfschmerzen,wasser,trinke'),
    ('Santé et corps', 'Hattest du letzte Woche eine Erkältung?', 'As-tu eu un rhume la semaine dernière ?', 'Ja, letzte Woche hatte ich eine Erkältung und musste zu Hause bleiben.', "Oui, la semaine dernière j'ai eu un rhume et j'ai dû rester à la maison.", 'erkältung,hatte,letzte'),
    ('Santé et corps', 'Was hilft dir bei einer Erkältung?', "Qu'est-ce qui t'aide quand tu as un rhume ?", 'Bei einer Erkältung helfen mir warmer Tee und viel Ruhe.', "Quand j'ai un rhume, du thé chaud et beaucoup de repos m'aident.", 'erkältung,tee,ruhe'),
    ('Santé et corps', 'Womit misst du Fieber?', 'Avec quoi mesures-tu la fièvre ?', 'Ich messe Fieber mit einem Thermometer.', 'Je mesure la fièvre avec un thermomètre.', 'fieber,thermometer,messe'),
    ('Santé et corps', 'Wie fühlst du dich nach dem Sport?', 'Comment te sens-tu après le sport ?', 'Nach dem Sport fühle ich mich müde, aber auch glücklich.', 'Après le sport, je me sens fatigué, mais aussi heureux.', 'sport,fühle,glücklich'),
    ('Santé et corps', 'Machst du regelmäßig Sport?', 'Fais-tu du sport régulièrement ?', 'Ja, ich mache zweimal pro Woche Sport.', 'Oui, je fais du sport deux fois par semaine.', 'sport,zweimal,woche'),
    ('Santé et corps', 'Was hast du gestern für deine Gesundheit getan?', "Qu'as-tu fait hier pour ta santé ?", 'Gestern bin ich eine Stunde spazieren gegangen und habe viel Wasser getrunken.', "Hier, je me suis promené pendant une heure et j'ai bu beaucoup d'eau.", 'gestern,spazieren,wasser'),
    ('Santé et corps', 'Hast du heute schon genug Wasser getrunken?', "As-tu déjà bu assez d'eau aujourd'hui ?", 'Nein, heute habe ich noch nicht genug Wasser getrunken.', "Non, aujourd'hui je n'ai pas encore bu assez d'eau.", 'wasser,getrunken,genug'),
    ('Santé et corps', 'Wie viel Wasser trinkst du pro Tag?', "Combien d'eau bois-tu par jour ?", 'Ich trinke ungefähr zwei Liter Wasser pro Tag.', "Je bois environ deux litres d'eau par jour.", 'liter,wasser,trinke'),
    ('Santé et corps', 'Wann warst du das letzte Mal beim Zahnarzt?', 'Quand es-tu allé chez le dentiste pour la dernière fois ?', 'Ich war vor drei Monaten beim Zahnarzt.', "J'étais chez le dentiste il y a trois mois.", 'zahnarzt,monaten,drei'),
    ('Santé et corps', 'Hast du Angst vor dem Zahnarzt?', 'As-tu peur du dentiste ?', 'Ja, ich habe ein bisschen Angst, weil der Bohrer so laut ist.', "Oui, j'ai un peu peur parce que la fraise est si bruyante.", 'angst,bohrer,laut'),
    ('Santé et corps', 'Wie oft putzt du dir die Zähne?', 'Combien de fois te brosses-tu les dents ?', 'Ich putze mir dreimal am Tag die Zähne.', 'Je me brosse les dents trois fois par jour.', 'zähne,putze,dreimal'),
    ('Santé et corps', 'Was tust du bei Zahnschmerzen?', 'Que fais-tu en cas de mal de dents ?', 'Bei Zahnschmerzen nehme ich eine Tablette und gehe zum Zahnarzt.', 'En cas de mal de dents, je prends un comprimé et je vais chez le dentiste.', 'zahnschmerzen,tablette,zahnarzt'),
    ('Santé et corps', 'Wie bekommst du einen Termin beim Arzt?', 'Comment obtiens-tu un rendez-vous chez le médecin ?', 'Ich rufe in der Praxis an und frage nach einem Termin.', "J'appelle le cabinet et je demande un rendez-vous.", 'termin,praxis,rufe'),
    ('Santé et corps', 'Du bist in der Arztpraxis. Was sagst du am Empfang?', "Tu es au cabinet médical. Que dis-tu à l'accueil ?", 'Guten Tag, ich habe einen Termin um zehn Uhr bei Doktor Müller.', "Bonjour, j'ai un rendez-vous à dix heures chez le docteur Müller.", 'termin,uhr,doktor'),
    ('Santé et corps', 'Gehst du zur Kontrolle zum Arzt, auch wenn du gesund bist?', 'Vas-tu chez le médecin pour un contrôle, même quand tu es en bonne santé ?', 'Ja, einmal im Jahr gehe ich zur Kontrolle, auch wenn ich gesund bin.', 'Oui, une fois par an je vais à un contrôle, même quand je suis en bonne santé.', 'kontrolle,jahr,gesund'),
    ('Santé et corps', 'Was sagst du dem Arzt, wenn du Bauchschmerzen hast?', 'Que dis-tu au médecin quand tu as mal au ventre ?', 'Ich habe seit gestern Bauchschmerzen und mir ist schlecht.', "J'ai mal au ventre depuis hier et j'ai mal au cœur.", 'bauchschmerzen,gestern,schlecht'),
    ('Santé et corps', 'Hast du manchmal Rückenschmerzen?', 'As-tu parfois mal au dos ?', 'Ja, manchmal tut mir der Rücken weh, weil ich den ganzen Tag am Computer sitze.', "Oui, parfois j'ai mal au dos parce que je suis assis toute la journée devant l'ordinateur.", 'rücken,computer,sitze'),
    ('Santé et corps', 'Welche Körperteile brauchst du beim Tanzen?', 'Quelles parties du corps utilises-tu pour danser ?', 'Beim Tanzen brauche ich die Beine, die Arme und den ganzen Körper.', "Pour danser, j'ai besoin des jambes, des bras et de tout le corps.", 'beine,arme,körper'),
    ('Santé et corps', 'Welche Körperteile tun dir nach dem Laufen weh?', 'Quelles parties du corps te font mal après la course ?', 'Nach dem Laufen tun mir die Beine und die Füße weh.', "Après la course, j'ai mal aux jambes et aux pieds.", 'beine,füße,laufen'),
    ('Santé et corps', 'Bist du Rechtshänder oder Linkshänder?', 'Es-tu droitier ou gaucher ?', 'Ich bin Rechtshänder und schreibe mit der rechten Hand.', "Je suis droitier et j'écris de la main droite.", 'rechtshänder,rechten,hand'),
    ('Santé et corps', 'Wie sehen deine Augen und deine Haare aus?', 'Comment sont tes yeux et tes cheveux ?', 'Ich habe braune Augen und kurze schwarze Haare.', "J'ai les yeux marron et les cheveux courts et noirs.", 'augen,haare,braune'),
    ('Santé et corps', 'Wie oft duschst du?', 'Combien de fois te douches-tu ?', 'Ich dusche jeden Morgen und jeden Abend, weil es in Yaoundé so heiß ist.', "Je me douche chaque matin et chaque soir parce qu'il fait si chaud à Yaoundé.", 'dusche,morgen,abend,heiß'),
    ('Santé et corps', 'Tun dir die Augen weh, wenn du lange am Handy bist?', 'Est-ce que tes yeux te font mal quand tu restes longtemps sur le téléphone ?', 'Ja, nach zwei Stunden am Handy tun mir die Augen weh.', "Oui, après deux heures sur le téléphone, j'ai mal aux yeux.", 'augen,handy,weh'),
    ('Santé et corps', 'Du bist in der Apotheke. Was sagst du?', 'Tu es à la pharmacie. Que dis-tu ?', 'Guten Tag, ich brauche etwas gegen Husten, bitte.', "Bonjour, j'ai besoin de quelque chose contre la toux, s'il vous plaît.", 'brauche,husten,gegen'),
    ('Santé et corps', 'Was kaufst du manchmal in der Apotheke?', "Qu'achètes-tu parfois à la pharmacie ?", 'In der Apotheke kaufe ich manchmal Hustensaft oder eine Salbe.', "À la pharmacie, j'achète parfois du sirop contre la toux ou une pommade.", 'apotheke,hustensaft,salbe,kaufe'),
    ('Santé et corps', 'Wo ist die nächste Apotheke bei dir?', 'Où est la pharmacie la plus proche de chez toi ?', 'Die nächste Apotheke ist neben dem Markt, nur fünf Minuten zu Fuß.', 'La pharmacie la plus proche est à côté du marché, à seulement cinq minutes à pied.', 'apotheke,markt,minuten'),
    ('Santé et corps', 'Liest du den Beipackzettel, bevor du eine Tablette nimmst?', 'Lis-tu la notice avant de prendre un comprimé ?', 'Ja, ich lese den Beipackzettel immer, bevor ich eine Tablette nehme.', 'Oui, je lis toujours la notice avant de prendre un comprimé.', 'beipackzettel,tablette,lese'),
    ('Santé et corps', 'Die Ärztin sagt „dreimal täglich“. Wann nimmst du die Tablette?', 'La médecin dit « trois fois par jour ». Quand prends-tu le comprimé ?', 'Ich nehme sie morgens, mittags und abends.', 'Je le prends le matin, à midi et le soir.', 'morgens,mittags,abends'),
    ('Santé et corps', 'Hast du zu Hause eine kleine Hausapotheke?', 'As-tu une petite pharmacie à la maison ?', 'Ja, ich habe zu Hause eine kleine Hausapotheke mit Pflastern und Tabletten.', "Oui, j'ai à la maison une petite pharmacie avec des pansements et des comprimés.", 'hausapotheke,pflastern,tabletten'),
    ('Santé et corps', 'Wann schläfst du besser, in der Regenzeit oder in der Trockenzeit?', 'Quand dors-tu mieux, pendant la saison des pluies ou pendant la saison sèche ?', 'In der Regenzeit schlafe ich besser, weil es nachts kühler ist.', "Pendant la saison des pluies, je dors mieux parce qu'il fait plus frais la nuit.", 'regenzeit,schlafe,besser,kühler'),
    ('Santé et corps', 'Was hilft dir, wenn du nicht einschlafen kannst?', "Qu'est-ce qui t'aide quand tu n'arrives pas à t'endormir ?", 'Wenn ich nicht einschlafen kann, hilft mir eine Tasse Tee.', "Quand je n'arrive pas à m'endormir, une tasse de thé m'aide.", 'einschlafen,tee,hilft'),
    ('Santé et corps', 'Hast du letzte Nacht gut geschlafen?', 'As-tu bien dormi la nuit dernière ?', 'Nein, letzte Nacht habe ich schlecht geschlafen, weil es so laut war.', "Non, la nuit dernière j'ai mal dormi parce qu'il y avait beaucoup de bruit.", 'geschlafen,nacht,laut'),
    ('Santé et corps', 'Machst du manchmal einen Mittagsschlaf?', 'Fais-tu parfois la sieste ?', 'Ja, nach dem Mittagessen mache ich oft einen kurzen Mittagsschlaf.', 'Oui, après le déjeuner, je fais souvent une courte sieste.', 'mittagsschlaf,kurzen,mittagessen'),
    ('Santé et corps', 'Bis wann hast du am Sonntag geschlafen?', "Jusqu'à quelle heure as-tu dormi dimanche ?", 'Am Sonntag habe ich bis neun Uhr geschlafen.', "Dimanche, j'ai dormi jusqu'à neuf heures.", 'sonntag,neun,geschlafen'),
    ('Santé et corps', 'Träumst du oft?', 'Rêves-tu souvent ?', 'Ja, ich träume oft, aber am Morgen vergesse ich meine Träume.', "Oui, je rêve souvent, mais le matin j'oublie mes rêves.", 'träume,vergesse,oft'),
    ('Santé et corps', 'Schläfst du lieber mit einem Ventilator oder bei offenem Fenster?', 'Préfères-tu dormir avec un ventilateur ou la fenêtre ouverte ?', 'Ich schlafe lieber mit einem Ventilator, weil es nachts oft heiß ist.', "Je préfère dormir avec un ventilateur parce qu'il fait souvent chaud la nuit.", 'ventilator,heiß,schlafe'),
    ('Santé et corps', 'Wie fühlst du dich am Montag?', 'Comment te sens-tu le lundi ?', 'Am Montag fühle ich mich ein bisschen gestresst, weil die Arbeit wieder beginnt.', 'Le lundi, je me sens un peu stressé parce que le travail recommence.', 'montag,fühle,gestresst'),
    ('Santé et corps', 'Was machst du, wenn du traurig bist?', 'Que fais-tu quand tu es triste ?', 'Wenn ich traurig bin, rufe ich meine beste Freundin an und wir reden.', "Quand je suis triste, j'appelle ma meilleure amie et nous parlons.", 'traurig,rufe,freundin'),
    ('Santé et corps', 'Wann bist du richtig glücklich?', 'Quand es-tu vraiment heureux ?', 'Ich bin richtig glücklich, wenn ich mit meiner Familie esse.', 'Je suis vraiment heureux quand je mange avec ma famille.', 'glücklich,familie,esse'),
    ('Santé et corps', 'Wann bist du nervös?', 'Quand es-tu nerveux ?', 'Ich bin nervös, wenn ich vor vielen Leuten sprechen muss.', 'Je suis nerveux quand je dois parler devant beaucoup de monde.', 'nervös,sprechen,leuten'),
    ('Santé et corps', 'Worüber hast du dich heute gefreut?', "Qu'est-ce qui t'a fait plaisir aujourd'hui ?", 'Heute habe ich mich über eine Nachricht von meiner Schwester gefreut.', "Aujourd'hui, j'ai été content d'un message de ma sœur.", 'gefreut,nachricht,schwester'),
    ('Santé et corps', 'Worüber hast du dich gestern geärgert?', "Qu'est-ce qui t'a énervé hier ?", 'Gestern habe ich mich über den Stau in Yaoundé geärgert, weil ich zu spät gekommen bin.', 'Hier, je me suis énervé à cause des embouteillages à Yaoundé, parce que je suis arrivé en retard.', 'geärgert,stau,yaoundé,spät'),
    ('Santé et corps', 'Was macht dir gute Laune?', "Qu'est-ce qui te met de bonne humeur ?", 'Musik und Tanzen machen mir gute Laune.', 'La musique et la danse me mettent de bonne humeur.', 'laune,musik,tanzen'),
    ('Santé et corps', 'Wie ist deine Stimmung am Abend?', 'Comment est ton humeur le soir ?', 'Am Abend bin ich meistens ruhig und entspannt.', 'Le soir, je suis la plupart du temps calme et détendu.', 'abend,ruhig,entspannt'),
    ('Santé et corps', 'Wann hast du zuletzt richtig laut gelacht?', 'Quand as-tu ri aux éclats pour la dernière fois ?', 'Gestern habe ich mit meinen Freunden richtig laut gelacht, weil ein Witz so lustig war.', "Hier, j'ai ri aux éclats avec mes amis parce qu'une blague était tellement drôle.", 'gelacht,freunden,witz'),
    ('Santé et corps', 'Mit wem sprichst du, wenn du Sorgen hast?', 'Avec qui parles-tu quand tu as des soucis ?', 'Wenn ich Sorgen habe, spreche ich mit meinem Bruder.', "Quand j'ai des soucis, je parle avec mon frère.", 'sorgen,spreche,bruder'),
    ('Santé et corps', 'Wie baust du Stress ab?', 'Comment évacues-tu le stress ?', 'Ich gehe spazieren und höre Musik, dann bin ich entspannt.', "Je vais me promener et j'écoute de la musique, ensuite je suis détendu.", 'spazieren,musik,entspannt'),
    ('Santé et corps', 'Hast du im Moment viel Stress?', 'As-tu beaucoup de stress en ce moment ?', 'Ja, im Moment habe ich viel Stress, weil ich für eine Prüfung lerne.', "Oui, en ce moment j'ai beaucoup de stress parce que je révise pour un examen.", 'stress,prüfung,lerne'),
    ('Santé et corps', 'Wie entspannst du dich am Wochenende?', 'Comment te détends-tu le week-end ?', 'Am Wochenende entspanne ich mich zu Hause und sehe einen Film.', 'Le week-end, je me détends à la maison et je regarde un film.', 'wochenende,entspanne,film'),
    ('Santé et corps', 'Möchtest du Yoga lernen?', 'Voudrais-tu apprendre le yoga ?', 'Ja, ich möchte Yoga lernen, weil es gegen Stress hilft.', 'Oui, je voudrais apprendre le yoga parce que ça aide contre le stress.', 'yoga,lernen,stress'),
    ('Santé et corps', 'Wie nutzt du eine kurze Pause bei Stress?', 'Comment utilises-tu une courte pause quand tu es stressé ?', 'In der Pause trinke ich einen Kaffee und gehe kurz an die frische Luft.', "Pendant la pause, je bois un café et je sors prendre l'air un moment.", 'pause,kaffee,luft'),
    ('Santé et corps', 'Wo kannst du in deiner Stadt gut entspannen?', 'Où peux-tu bien te détendre dans ta ville ?', 'Ich kann im Garten meiner Tante gut entspannen, dort ist es ruhig.', "Je peux bien me détendre dans le jardin de ma tante, c'est calme là-bas.", 'garten,entspannen,ruhig'),
    ('Santé et corps', 'Isst du jeden Tag Obst oder Gemüse?', 'Manges-tu des fruits ou des légumes tous les jours ?', 'Ja, jeden Tag esse ich Obst, zum Beispiel Mango und Bananen.', 'Oui, je mange des fruits tous les jours, par exemple des mangues et des bananes.', 'obst,mango,bananen'),
    ('Santé et corps', 'Was ist für dich ein gesundes Frühstück?', "Pour toi, qu'est-ce qu'un petit-déjeuner sain ?", 'Ein gesundes Frühstück ist für mich Brot mit Ei und eine Papaya.', "Pour moi, un petit-déjeuner sain, c'est du pain avec un œuf et une papaye.", 'papaya,brot,frühstück'),
    ('Santé et corps', 'Isst du lieber Obst oder Süßigkeiten?', 'Préfères-tu manger des fruits ou des bonbons ?', 'Ich esse lieber Obst, weil Süßigkeiten nicht gesund sind.', 'Je préfère manger des fruits parce que les bonbons ne sont pas sains.', 'obst,süßigkeiten,gesund'),
    ('Santé et corps', 'Findest du Ndolé gesund?', 'Trouves-tu que le ndolé est sain ?', 'Ja, ich finde Ndolé gesund, weil es Blätter, Fisch und Erdnüsse enthält.', "Oui, je trouve le ndolé sain parce qu'il contient des feuilles, du poisson et des arachides.", 'ndolé,gesund,blätter,fisch'),
    ('Santé et corps', 'Was isst du selten, weil es nicht gesund ist?', "Que manges-tu rarement parce que ce n'est pas sain ?", 'Ich esse selten Pommes, weil sie sehr fettig sind.', "Je mange rarement des frites parce qu'elles sont très grasses.", 'pommes,selten,fettig'),
    ('Santé et corps', 'Wie viel Zucker nimmst du in den Tee?', 'Combien de sucre mets-tu dans ton thé ?', 'Ich nehme nur einen Löffel Zucker in den Tee.', "Je ne prends qu'une cuillère de sucre dans mon thé.", 'zucker,löffel,tee'),
    ('Santé et corps', 'Was hast du heute zum Mittagessen gegessen?', "Qu'as-tu mangé ce midi ?", 'Heute habe ich Reis mit Hähnchen und Salat gegessen.', "Aujourd'hui, j'ai mangé du riz avec du poulet et de la salade.", 'reis,hähnchen,salat'),
    ('Santé et corps', 'Isst du abends früh oder spät?', 'Manges-tu tôt ou tard le soir ?', 'Ich esse abends früh, meistens um sieben Uhr.', 'Le soir, je mange tôt, la plupart du temps à sept heures.', 'abends,früh,sieben'),
    ('Santé et corps', 'Welches Gemüse isst du am liebsten?', 'Quel légume préfères-tu manger ?', 'Am liebsten esse ich Okra und Tomaten.', 'Ce que je préfère manger, ce sont le gombo et les tomates.', 'okra,tomaten,liebsten'),
    ('Santé et corps', 'Kochst du selbst oder isst du oft auf der Straße?', 'Cuisines-tu toi-même ou manges-tu souvent dans la rue ?', 'Meistens koche ich selbst, aber manchmal kaufe ich Beignets auf der Straße.', "La plupart du temps, je cuisine moi-même, mais parfois j'achète des beignets dans la rue.", 'koche,selbst,beignets,straße'),
    ('Santé et corps', 'Warum ist Wasser gesünder als Limonade?', "Pourquoi l'eau est-elle plus saine que la limonade ?", 'Wasser ist gesünder, weil Limonade sehr viel Zucker hat.', "L'eau est plus saine parce que la limonade contient énormément de sucre.", 'wasser,gesünder,limonade,zucker'),
    ('Santé et corps', 'Willst du nächstes Jahr mehr Sport machen?', "Veux-tu faire plus de sport l'année prochaine ?", 'Ja, nächstes Jahr will ich dreimal pro Woche Sport machen.', "Oui, l'année prochaine, je veux faire du sport trois fois par semaine.", 'nächstes,sport,dreimal'),
    ('Santé et corps', 'Gehst du lieber zu Fuß oder nimmst du ein Moto-Taxi?', 'Préfères-tu marcher ou prendre une moto-taxi ?', 'Ich gehe lieber zu Fuß, das ist gesund und kostet nichts.', "Je préfère marcher, c'est bon pour la santé et ça ne coûte rien.", 'fuß,gesund,gehe,kostet'),
    ('Santé et corps', 'Kannst du schwimmen?', 'Sais-tu nager ?', 'Ja, ich kann gut schwimmen. Ich habe es als Kind gelernt.', "Oui, je sais bien nager. Je l'ai appris quand j'étais enfant.", 'schwimmen,kann,gelernt'),
    ('Santé et corps', 'Was findest du wichtiger für die Gesundheit: Schlaf oder Sport?', "Qu'est-ce qui est plus important pour la santé, selon toi : le sommeil ou le sport ?", 'Ich finde Schlaf wichtiger, weil ich ohne Schlaf keine Energie habe.', "Je trouve le sommeil plus important parce que sans sommeil, je n'ai pas d'énergie.", 'schlaf,wichtiger,energie'),
    ('Santé et corps', 'Was hältst du von Sport am frühen Morgen?', 'Que penses-tu du sport tôt le matin ?', 'Ich finde Sport am frühen Morgen gut, denn dann bin ich den ganzen Tag wach.', 'Je trouve le sport tôt le matin bien, car ensuite je suis éveillé toute la journée.', 'morgen,wach,sport'),
    ('Santé et corps', 'Dein Freund ist krank. Was sagst du ihm?', 'Ton ami est malade. Que lui dis-tu ?', 'Ich sage ihm: Bleib im Bett und trink viel Tee!', 'Je lui dis : reste au lit et bois beaucoup de thé !', 'bett,tee,trink'),
    ('Santé et corps', 'Du hast dich in den Finger geschnitten. Was machst du?', "Tu t'es coupé le doigt. Que fais-tu ?", 'Ich wasche meinen Finger mit Wasser und Seife und klebe ein Pflaster darauf.', "Je lave mon doigt avec de l'eau et du savon et je colle un pansement dessus.", 'finger,seife,pflaster,wasche'),
    ('Santé et corps', 'Du bist krank und kannst nicht zur Arbeit gehen. Was sagst du deinem Chef?', 'Tu es malade et tu ne peux pas aller travailler. Que dis-tu à ton chef ?', 'Guten Morgen, ich bin leider krank und kann heute nicht kommen.', "Bonjour, je suis malheureusement malade et je ne peux pas venir aujourd'hui.", 'krank,leider,kommen'),
    ('Santé et corps', 'Was trinkst du, wenn du Halsschmerzen hast?', 'Que bois-tu quand tu as mal à la gorge ?', 'Dann trinke ich heißen Ingwertee mit Honig.', 'Alors je bois du thé chaud au gingembre avec du miel.', 'ingwertee,honig,trinke'),
    ('Santé et corps', 'Wie schützt du dich vor der Sonne?', 'Comment te protèges-tu du soleil ?', 'Ich trage einen Hut und bleibe mittags im Schatten.', "Je porte un chapeau et je reste à l'ombre à midi.", 'hut,schatten,trage'),
    ('Santé et corps', 'Schläfst du unter einem Moskitonetz?', 'Dors-tu sous une moustiquaire ?', 'Ja, ich schlafe jede Nacht unter einem Moskitonetz, damit mich keine Mücken stechen.', 'Oui, je dors chaque nuit sous une moustiquaire pour que les moustiques ne me piquent pas.', 'moskitonetz,mücken,schlafe'),
    ('Santé et corps', 'Warst du schon einmal im Krankenhaus?', "Es-tu déjà allé à l'hôpital ?", 'Ja, als Kind musste ich drei Tage im Krankenhaus bleiben, weil ich Malaria hatte.', "Oui, enfant, j'ai dû rester trois jours à l'hôpital parce que j'avais le paludisme.", 'krankenhaus,malaria,kind'),
    ('Santé et corps', 'Wer hat dir geholfen, als du zuletzt krank warst?', "Qui t'a aidé la dernière fois que tu étais malade ?", 'Meine Mutter hat mir geholfen und eine Suppe für mich gekocht.', "Ma mère m'a aidé et a préparé une soupe pour moi.", 'mutter,geholfen,suppe'),
    ('Santé et corps', 'Hast du heute Morgen schon etwas gegessen?', 'As-tu déjà mangé quelque chose ce matin ?', 'Ja, ich habe heute Morgen zwei Eier und ein Stück Brot gegessen.', "Oui, ce matin j'ai mangé deux œufs et un morceau de pain.", 'gegessen,eier,brot'),
    ('Santé et corps', 'Wann hast du zuletzt Sport gemacht?', 'Quand as-tu fait du sport pour la dernière fois ?', 'Vor zwei Tagen bin ich fünf Kilometer gelaufen.', "Il y a deux jours, j'ai couru cinq kilomètres.", 'kilometer,gelaufen,tagen'),
    ('Santé et corps', 'Hast du dich als Kind oft verletzt?', "T'es-tu souvent blessé quand tu étais enfant ?", 'Ja, als Kind bin ich oft vom Baum gefallen und habe mir das Knie verletzt.', "Oui, enfant, je suis souvent tombé de l'arbre et je me suis blessé au genou.", 'knie,gefallen,baum'),
    ('Santé et corps', 'Was möchtest du für deine Gesundheit ändern?', 'Que voudrais-tu changer pour ta santé ?', 'Ich möchte früher ins Bett gehen und mehr Gemüse essen.', 'Je voudrais me coucher plus tôt et manger plus de légumes.', 'früher,gemüse,möchte'),
    ('Santé et corps', 'Was machst du morgen, um dich zu entspannen?', 'Que fais-tu demain pour te détendre ?', 'Morgen mache ich einen langen Spaziergang und koche etwas Leckeres.', 'Demain, je fais une longue promenade et je cuisine quelque chose de bon.', 'morgen,spaziergang,koche'),
    ('Santé et corps', 'Wann hast du deinen nächsten Termin beim Arzt?', 'Quand as-tu ton prochain rendez-vous chez le médecin ?', 'Mein nächster Termin beim Arzt ist am Donnerstag um neun Uhr.', 'Mon prochain rendez-vous chez le médecin est jeudi à neuf heures.', 'termin,donnerstag,neun'),
    ('Santé et corps', 'Was würdest du tun, um gesünder zu leben?', 'Que ferais-tu pour vivre plus sainement ?', 'Ich würde jeden Tag eine Stunde laufen und kein Fastfood mehr essen.', 'Je courrais une heure par jour et je ne mangerais plus de fast-food.', 'würde,laufen,fastfood'),
    ('Santé et corps', 'Erzähl mir von deinem letzten Arztbesuch.', 'Raconte-moi ta dernière visite chez le médecin.', 'Im Oktober war ich beim Arzt, weil ich Husten hatte. Er hat mir Medizin gegeben und nach drei Tagen war ich wieder gesund.', "En octobre, j'étais chez le médecin parce que je toussais. Il m'a donné un médicament et après trois jours j'allais de nouveau bien.", 'arzt,husten,medizin,gesund'),
    ('Santé et corps', 'Erzähl mir von einem Tag, an dem du richtig krank warst.', 'Raconte-moi un jour où tu étais vraiment malade.', 'Letztes Jahr hatte ich eine starke Grippe. Ich hatte Fieber und bin eine Woche im Bett geblieben.', "L'année dernière, j'ai eu une forte grippe. J'avais de la fièvre et je suis resté une semaine au lit.", 'grippe,fieber,bett'),
    ('Santé et corps', 'Beschreibe einen gesunden Tag in deinem Leben.', 'Décris une journée saine dans ta vie.', 'An einem gesunden Tag laufe ich morgens, esse viel Obst und gehe früh schlafen.', "Lors d'une journée saine, je cours le matin, je mange beaucoup de fruits et je me couche tôt.", 'gesunden,laufe,obst'),
    ('Santé et corps', 'Beschreibe, wie du dich nach einem langen Tag entspannst.', 'Décris comment tu te détends après une longue journée.', 'Nach einem langen Tag nehme ich eine warme Dusche, esse etwas und sehe fern.', 'Après une longue journée, je prends une douche chaude, je mange quelque chose et je regarde la télévision.', 'dusche,fern,langen'),
    ('Santé et corps', 'Wirst du schnell krank, wenn es regnet?', 'Tombes-tu vite malade quand il pleut ?', 'Ja, wenn ich im Regen nass werde, bekomme ich schnell Husten.', 'Oui, quand je suis mouillé par la pluie, je tousse vite.', 'regen,nass,husten'),
    ('Santé et corps', 'Was findest du schwieriger: früh aufstehen oder früh schlafen gehen?', "Qu'est-ce que tu trouves plus difficile : se lever tôt ou se coucher tôt ?", 'Ich finde es schwieriger, früh aufzustehen, weil ich abends lange wach bin.', 'Je trouve plus difficile de me lever tôt parce que le soir je reste éveillé longtemps.', 'schwieriger,aufzustehen,wach'),
    ('Santé et corps', 'Was hältst du von Energy-Drinks?', 'Que penses-tu des boissons énergisantes ?', 'Ich halte nicht viel davon, denn sie sind teuer und nicht gut für das Herz.', "Je n'en pense pas beaucoup de bien, car elles sont chères et mauvaises pour le cœur.", 'teuer,herz,halte'),
    ('Santé et corps', 'Was kaufst du auf dem Markt, wenn du gesund essen willst?', "Qu'achètes-tu au marché quand tu veux manger sainement ?", 'Auf dem Markt kaufe ich frischen Fisch, Bananen und Erdnüsse.', "Au marché, j'achète du poisson frais, des bananes et des arachides.", 'markt,fisch,bananen,frischen'),
    ('Météo et nature', 'Wie ist das Wetter heute?', "Quel temps fait-il aujourd'hui ?", 'Heute ist das Wetter schön. Die Sonne scheint und es ist warm.', "Aujourd'hui, il fait beau. Le soleil brille et il fait chaud.", 'wetter,sonne,warm,schön'),
    ('Météo et nature', 'Wann ist die Sonne bei euch am heißesten?', 'Quand le soleil est-il le plus chaud chez vous ?', 'Die Sonne ist mittags am heißesten, ungefähr um zwölf Uhr.', 'Le soleil est le plus chaud à midi, vers douze heures.', 'sonne,mittags,heißesten'),
    ('Météo et nature', 'Was siehst du gerade aus dem Fenster?', 'Que vois-tu en ce moment par la fenêtre ?', 'Ich sehe dunkle Wolken und ein paar Bäume. Gleich fängt es an zu regnen.', 'Je vois des nuages sombres et quelques arbres. Il va bientôt se mettre à pleuvoir.', 'wolken,bäume,regnen,dunkle'),
    ('Météo et nature', 'Gibt es bei dir morgens manchmal Nebel?', 'Y a-t-il parfois du brouillard le matin chez toi ?', 'Ja, in der Trockenzeit gibt es morgens oft Nebel. Dann sehe ich kaum etwas.', 'Oui, pendant la saison sèche, il y a souvent du brouillard le matin. Alors je ne vois presque rien.', 'nebel,morgens,trockenzeit'),
    ('Météo et nature', 'Wie viele Jahreszeiten gibt es in Deutschland?', 'Combien de saisons y a-t-il en Allemagne ?', 'In Deutschland gibt es vier Jahreszeiten: Frühling, Sommer, Herbst und Winter.', "En Allemagne, il y a quatre saisons : le printemps, l'été, l'automne et l'hiver.", 'vier,jahreszeiten,frühling,herbst'),
    ('Météo et nature', 'Welche Jahreszeiten kennst du aus deiner Heimat?', "Quelles saisons connais-tu dans ton pays d'origine ?", 'In meiner Heimat gibt es zwei Jahreszeiten: die Regenzeit und die Trockenzeit.', 'Dans mon pays, il y a deux saisons : la saison des pluies et la saison sèche.', 'regenzeit,trockenzeit,heimat'),
    ('Météo et nature', 'Wann beginnt in Yaoundé die Regenzeit?', 'Quand commence la saison des pluies à Yaoundé ?', 'Ich glaube, die Regenzeit beginnt im März. Dann regnet es oft am Nachmittag.', "Je crois que la saison des pluies commence en mars. Alors il pleut souvent l'après-midi.", 'regenzeit,märz,nachmittag'),
    ('Météo et nature', 'Wie findest du die Regenzeit?', 'Comment trouves-tu la saison des pluies ?', 'Ich finde die Regenzeit schön, weil die Luft dann frisch ist und alles grün wird.', "Je trouve la saison des pluies agréable, parce que l'air est alors frais et que tout devient vert.", 'regenzeit,frisch,grün'),
    ('Météo et nature', 'Was machst du bei starkem Regen zu Hause?', 'Que fais-tu à la maison quand il pleut fort ?', 'Bei starkem Regen sehe ich einen Film und esse Erdnüsse.', 'Quand il pleut fort, je regarde un film et je mange des arachides.', 'regen,film,erdnüsse'),
    ('Météo et nature', 'Hast du immer einen Regenschirm dabei?', 'As-tu toujours un parapluie sur toi ?', 'Ja, in der Regenzeit habe ich immer einen kleinen Regenschirm in der Tasche.', "Oui, pendant la saison des pluies, j'ai toujours un petit parapluie dans mon sac.", 'regenschirm,regenzeit,tasche'),
    ('Météo et nature', 'Wie ist das Wetter im Winter in Deutschland?', 'Quel temps fait-il en hiver en Allemagne ?', 'Ich glaube, im Winter ist es in Deutschland sehr kalt. Manchmal gibt es Schnee.', "Je crois qu'en hiver, il fait très froid en Allemagne. Parfois, il y a de la neige.", 'winter,kalt,schnee,glaube'),
    ('Météo et nature', 'Hast du jemals Schnee gesehen?', 'As-tu déjà vu de la neige un jour ?', 'Nein, ich habe noch nie Schnee gesehen. Ich möchte ihn gern einmal sehen.', "Non, je n'ai encore jamais vu de neige. J'aimerais bien la voir une fois.", 'schnee,gesehen,möchte'),
    ('Météo et nature', 'Wie viel Grad sind es heute ungefähr?', "Combien de degrés fait-il environ aujourd'hui ?", 'Heute sind es ungefähr 28 Grad. Es ist ziemlich warm.', "Aujourd'hui, il fait environ 28 degrés. Il fait assez chaud.", 'grad,ungefähr,warm'),
    ('Météo et nature', 'Ist es bei dir heute heiß oder kalt?', "Chez toi, aujourd'hui, fait-il chaud ou froid ?", 'Bei mir ist es heute heiß. Ich trinke viel Wasser.', "Chez moi, il fait chaud aujourd'hui. Je bois beaucoup d'eau.", 'heiß,wasser,trinke'),
    ('Météo et nature', 'Was trägst du bei kaltem Wetter?', 'Que portes-tu quand il fait froid ?', 'Bei kaltem Wetter trage ich einen Pullover und eine lange Hose.', 'Quand il fait froid, je porte un pull et un pantalon long.', 'pullover,trage,hose'),
    ('Météo et nature', 'Was ziehst du an, wenn es sehr heiß ist?', 'Que mets-tu quand il fait très chaud ?', 'Wenn es sehr heiß ist, ziehe ich ein leichtes T-Shirt und kurze Hosen an.', 'Quand il fait très chaud, je mets un t-shirt léger et un short.', 'ziehe,t-shirt,heiß'),
    ('Météo et nature', 'Was trägst du in der Regenzeit an den Füßen?', 'Que portes-tu aux pieds pendant la saison des pluies ?', 'In der Regenzeit trage ich Gummistiefel, damit meine Füße trocken bleiben.', 'Pendant la saison des pluies, je porte des bottes en caoutchouc pour que mes pieds restent secs.', 'gummistiefel,regenzeit,füße,trocken'),
    ('Météo et nature', 'Hast du gestern den Wetterbericht gesehen?', 'As-tu vu hier la météo ?', 'Ja, ich habe gestern den Wetterbericht gesehen. Heute soll es regnen.', "Oui, j'ai vu la météo hier. Aujourd'hui, il doit pleuvoir.", 'wetterbericht,gesehen,regnen'),
    ('Météo et nature', 'Wo schaust du dir die Wettervorhersage an?', 'Où regardes-tu les prévisions météo ?', 'Ich schaue mir die Wettervorhersage auf meinem Handy an. Ich benutze eine Wetter-App.', "Je regarde les prévisions météo sur mon téléphone. J'utilise une application météo.", 'wettervorhersage,handy,app'),
    ('Météo et nature', 'Wie wird das Wetter morgen?', 'Quel temps fera-t-il demain ?', 'Morgen wird es sonnig, aber am Abend kommt vielleicht Regen.', 'Demain, il fera beau, mais le soir il y aura peut-être de la pluie.', 'morgen,sonnig,regen'),
    ('Météo et nature', 'Was hast du bei schönem Wetter zuletzt mit Freunden gemacht?', "Qu'as-tu fait avec des amis la dernière fois qu'il faisait beau ?", 'Bei schönem Wetter haben wir im Hof gesessen und Karten gespielt.', 'Quand il faisait beau, nous nous sommes assis dans la cour et avons joué aux cartes.', 'wetter,hof,gesessen,karten'),
    ('Météo et nature', 'Wie hast du dein letztes Wochenende in der Natur verbracht?', 'Comment as-tu passé ton dernier week-end dans la nature ?', 'Am Wochenende habe ich einen langen Spaziergang im Park gemacht.', "Le week-end, j'ai fait une longue promenade dans le parc.", 'wochenende,spaziergang,park'),
    ('Météo et nature', 'Gehst du lieber in den Wald oder in den Park?', 'Préfères-tu aller dans la forêt ou dans le parc ?', 'Ich gehe lieber in den Wald, weil es dort ruhiger ist als im Park.', "Je préfère aller dans la forêt, parce qu'il y fait plus calme que dans le parc.", 'wald,park,ruhiger,lieber'),
    ('Météo et nature', 'Was siehst du, wenn du durch den Wald gehst?', 'Que vois-tu quand tu te promènes dans la forêt ?', 'Im Wald sehe ich viele hohe Bäume, bunte Vögel und manchmal ein Eichhörnchen.', 'Dans la forêt, je vois beaucoup de grands arbres, des oiseaux colorés et parfois un écureuil.', 'wald,bäume,vögel,eichhörnchen'),
    ('Météo et nature', 'Magst du lieber das Meer oder die Berge?', 'Préfères-tu la mer ou les montagnes ?', 'Ich mag lieber die Berge, weil es dort kühl ist und die Aussicht schön ist.', "Je préfère les montagnes, parce qu'il y fait frais et que la vue est belle.", 'berge,kühl,aussicht,lieber'),
    ('Météo et nature', 'Kennst du einen hohen Berg in Kamerun?', 'Connais-tu une haute montagne au Cameroun ?', 'Ja, ich kenne den Kamerunberg. Er ist ein hoher Vulkan in der Nähe von Buea.', "Oui, je connais le mont Cameroun. C'est un haut volcan près de Buea.", 'kamerunberg,vulkan,berg,buea'),
    ('Météo et nature', 'Welches Haustier möchtest du gern haben?', 'Quel animal de compagnie aimerais-tu avoir ?', 'Ich möchte gern einen Hund haben, weil Hunde das Haus beschützen.', "J'aimerais avoir un chien, parce que les chiens protègent la maison.", 'hund,möchte,beschützen,haus'),
    ('Météo et nature', 'Hast du ein Haustier zu Hause?', 'As-tu un animal de compagnie à la maison ?', 'Ja, ich habe eine Katze. Sie heißt Mimi und schläft oft auf dem Sofa.', "Oui, j'ai une chatte. Elle s'appelle Mimi et dort souvent sur le canapé.", 'katze,heißt,sofa,schläft'),
    ('Météo et nature', 'Magst du Hunde oder Katzen lieber?', 'Préfères-tu les chiens ou les chats ?', 'Ich mag Hunde lieber, denn sie sind treu und spielen gern mit mir.', 'Je préfère les chiens, car ils sont fidèles et aiment jouer avec moi.', 'hunde,treu,lieber,spielen'),
    ('Météo et nature', 'Welches Tier findest du am schönsten?', 'Quel animal trouves-tu le plus beau ?', 'Ich finde den Löwen am schönsten, weil er stark und mutig ist.', "Je trouve le lion le plus beau, parce qu'il est fort et courageux.", 'löwen,schönsten,stark'),
    ('Météo et nature', 'Welche wilden Tiere gibt es in Kamerun?', 'Quels animaux sauvages y a-t-il au Cameroun ?', 'Ich weiß, dass es in Kamerun Affen, Papageien und Krokodile gibt.', "Je sais qu'au Cameroun, il y a des singes, des perroquets et des crocodiles.", 'affen,papageien,krokodile,kamerun'),
    ('Météo et nature', 'Vor welchem Tier hast du Angst?', 'De quel animal as-tu peur ?', 'Ich habe Angst vor Schlangen, weil sie gefährlich sein können.', "J'ai peur des serpents, parce qu'ils peuvent être dangereux.", 'angst,schlangen,gefährlich'),
    ('Météo et nature', 'Warst du schon einmal im Zoo?', 'As-tu déjà été au zoo ?', 'Ja, als Kind war ich im Zoo. Ich habe dort einen Elefanten gesehen.', "Oui, enfant, je suis allé au zoo. J'y ai vu un éléphant.", 'zoo,elefanten,kind'),
    ('Météo et nature', 'Welche Tiere kann man auf dem Land sehen?', 'Quels animaux peut-on voir à la campagne ?', 'Auf dem Land sehe ich oft Kühe, Schafe und Pferde.', 'À la campagne, je vois souvent des vaches, des moutons et des chevaux.', 'land,kühe,schafe,pferde'),
    ('Météo et nature', 'Hast du Tiere im Dorf deiner Familie?', 'Y a-t-il des animaux dans le village de ta famille ?', 'Ja, mein Onkel hat im Dorf zehn Hühner und zwei Ziegen.', 'Oui, mon oncle a dix poules et deux chèvres au village.', 'dorf,hühner,ziegen,onkel'),
    ('Météo et nature', 'Was für Pflanzen hast du zu Hause?', 'Quelles plantes as-tu à la maison ?', 'Ich habe ein paar Blumen auf dem Balkon und einen kleinen Zitronenbaum im Hof.', "J'ai quelques fleurs sur le balcon et un petit citronnier dans la cour.", 'blumen,balkon,zitronenbaum,hof'),
    ('Météo et nature', 'Welche Blume gefällt dir am besten?', 'Quelle fleur te plaît le plus ?', 'Mir gefällt die Rose am besten. Sie riecht gut und ist rot.', "C'est la rose qui me plaît le plus. Elle sent bon et elle est rouge.", 'rose,riecht,gefällt,rot'),
    ('Météo et nature', 'Wie sieht der Garten deiner Familie aus?', 'À quoi ressemble le jardin de ta famille ?', 'Unser Garten ist klein, aber schön. Dort wachsen Bananen und Papayas.', 'Notre jardin est petit mais joli. Il y pousse des bananes et des papayes.', 'garten,bananen,papayas,wachsen'),
    ('Météo et nature', 'Was möchtest du nächstes Jahr in deinem Garten pflanzen?', "Que voudrais-tu planter dans ton jardin l'année prochaine ?", 'Nächstes Jahr möchte ich Tomaten und Zwiebeln pflanzen, denn ich esse sie jeden Tag.', "L'année prochaine, je voudrais planter des tomates et des oignons, car j'en mange tous les jours.", 'pflanzen,tomaten,zwiebeln,möchte'),
    ('Météo et nature', 'Wie oft gießt du deine Pflanzen?', 'À quelle fréquence arroses-tu tes plantes ?', 'Ich gieße meine Pflanzen jeden Morgen. In der Trockenzeit brauchen sie viel Wasser.', "J'arrose mes plantes tous les matins. Pendant la saison sèche, elles ont besoin de beaucoup d'eau.", 'gieße,pflanzen,wasser,morgen'),
    ('Météo et nature', 'Gibt es einen großen Baum bei dir in der Nähe?', 'Y a-t-il un grand arbre près de chez toi ?', 'Ja, vor unserem Haus steht ein großer Mangobaum. Die Kinder spielen gern darunter.', 'Oui, devant notre maison, il y a un grand manguier. Les enfants aiment jouer dessous.', 'baum,mangobaum,kinder'),
    ('Météo et nature', 'Wann ist die Trockenzeit in Kamerun?', 'Quand a lieu la saison sèche au Cameroun ?', 'Die Trockenzeit beginnt im November. Dann regnet es fast nie und es ist oft staubig.', "La saison sèche commence en novembre. Alors il ne pleut presque jamais et c'est souvent poussiéreux.", 'trockenzeit,november,staubig'),
    ('Météo et nature', 'Wie verändert sich die Natur in der Trockenzeit?', 'Comment la nature change-t-elle pendant la saison sèche ?', 'In der Trockenzeit werden die Blätter gelb und das Gras wird trocken.', "Pendant la saison sèche, les feuilles jaunissent et l'herbe devient sèche.", 'trockenzeit,blätter,gras,trocken'),
    ('Météo et nature', 'Was findest du an der Trockenzeit unangenehm?', "Qu'est-ce que tu trouves désagréable dans la saison sèche ?", 'Ich finde den Staub unangenehm, weil er überall in der Luft ist.', "Je trouve la poussière désagréable, parce qu'elle est partout dans l'air.", 'staub,unangenehm,luft'),
    ('Météo et nature', 'Wie kommst du bei Regen zur Arbeit oder zur Schule?', "Comment vas-tu au travail ou à l'école quand il pleut ?", 'Wenn es stark regnet, nehme ich ein Taxi, weil ich nicht nass werden möchte.', 'Quand il pleut fort, je prends un taxi, parce que je ne veux pas être mouillé.', 'regnet,taxi,nass'),
    ('Météo et nature', 'Du stehst an der Straße und es regnet. Was machst du?', 'Tu es au bord de la route et il pleut. Que fais-tu ?', 'Ich warte unter einem Dach, bis der Regen aufhört.', "J'attends sous un toit jusqu'à ce que la pluie s'arrête.", 'warte,dach,regen,aufhört'),
    ('Météo et nature', 'Es gibt ein Gewitter und der Strom fällt aus. Was machst du?', 'Il y a un orage et le courant est coupé. Que fais-tu ?', 'Ich zünde eine Kerze an und warte, bis der Strom wieder da ist.', "J'allume une bougie et j'attends que le courant revienne.", 'kerze,strom,warte,zünde'),
    ('Météo et nature', 'Was hast du gemacht, als es gestern so stark geregnet hat?', "Qu'as-tu fait quand il a plu aussi fort hier ?", 'Ich habe zu Hause gelesen und Musik gehört, weil der Regen so laut war.', "J'ai lu à la maison et écouté de la musique, parce que la pluie était si bruyante.", 'gelesen,musik,regen'),
    ('Météo et nature', 'Wie sieht der Himmel heute aus?', "À quoi ressemble le ciel aujourd'hui ?", 'Der Himmel ist heute bewölkt. Ich sehe viele graue Wolken.', "Le ciel est nuageux aujourd'hui. Je vois beaucoup de nuages gris.", 'himmel,bewölkt,wolken'),
    ('Météo et nature', 'Hast du schon einmal einen Regenbogen gesehen?', 'As-tu déjà vu un arc-en-ciel ?', 'Ja, nach einem starken Regen habe ich einmal einen großen Regenbogen gesehen.', "Oui, après une forte pluie, j'ai vu une fois un grand arc-en-ciel.", 'regenbogen,gesehen,regen'),
    ('Météo et nature', 'Wann schaust du dir die Sterne an?', 'Quand regardes-tu les étoiles ?', 'Ich schaue mir abends die Sterne an, wenn der Himmel klar ist.', 'Je regarde les étoiles le soir, quand le ciel est dégagé.', 'sterne,abends,himmel,klar'),
    ('Météo et nature', 'Um wie viel Uhr geht in Kamerun die Sonne unter?', 'À quelle heure le soleil se couche-t-il au Cameroun ?', 'In Kamerun geht die Sonne ungefähr um 18 Uhr unter. Dann wird es schnell dunkel.', 'Au Cameroun, le soleil se couche vers 18 heures. Ensuite, il fait vite nuit.', 'sonne,uhr,dunkel'),
    ('Météo et nature', 'Was ist der größte Unterschied zwischen dem Wetter in Kamerun und in Deutschland?', 'Quelle est la plus grande différence entre le temps au Cameroun et en Allemagne ?', 'Ich glaube, in Deutschland ist es im Winter sehr kalt, aber in Kamerun ist es immer warm.', "Je crois qu'en Allemagne, il fait très froid en hiver, mais qu'au Cameroun il fait toujours chaud.", 'kalt,warm,winter,deutschland'),
    ('Météo et nature', 'Würdest du gern in einem kalten Land leben?', 'Aimerais-tu vivre dans un pays froid ?', 'Nein, ich würde nicht gern in einem kalten Land leben. Ich mag die Wärme.', "Non, je n'aimerais pas vivre dans un pays froid. J'aime la chaleur.", 'kalten,land,wärme,würde'),
    ('Météo et nature', 'Erzähl mir von deiner Lieblingsjahreszeit.', 'Parle-moi de ta saison préférée.', 'Meine Lieblingsjahreszeit ist die Trockenzeit. Dann scheint die Sonne, und ich gehe oft mit meiner Familie an den Fluss.', 'Ma saison préférée est la saison sèche. Alors le soleil brille et je vais souvent à la rivière avec ma famille.', 'lieblingsjahreszeit,trockenzeit,sonne,fluss'),
    ('Météo et nature', 'Welche Jahreszeit gefällt dir nicht so gut?', 'Quelle saison te plaît moins ?', 'Die Zeit vor der Regenzeit gefällt mir nicht, weil es dann sehr heiß ist.', "La période avant la saison des pluies ne me plaît pas, parce qu'il fait alors très chaud.", 'gefällt,regenzeit,heiß'),
    ('Météo et nature', 'Du siehst Müll am Fluss. Was machst du?', 'Tu vois des déchets près de la rivière. Que fais-tu ?', 'Ich nehme den Müll mit und werfe ihn in den Mülleimer.', "J'emporte les déchets et je les jette à la poubelle.", 'müll,mülleimer,werfe'),
    ('Météo et nature', 'Was machst du mit leeren Plastikflaschen?', 'Que fais-tu des bouteilles en plastique vides ?', 'Ich benutze sie noch einmal und fülle Wasser hinein.', "Je les réutilise et j'y mets de l'eau.", 'benutze,wasser,hinein,einmal'),
    ('Météo et nature', 'Was möchtest du für die Umwelt in deiner Stadt tun?', "Que voudrais-tu faire pour l'environnement dans ta ville ?", 'Ich möchte mit meinen Nachbarn den Müll in unserer Straße sammeln.', 'Je voudrais ramasser les déchets de notre rue avec mes voisins.', 'müll,sammeln,möchte,nachbarn'),
    ('Météo et nature', 'Wie schützt du die Umwelt im Alltag?', "Comment protèges-tu l'environnement au quotidien ?", 'Ich benutze eine Stofftasche und kaufe weniger Plastik.', "J'utilise un sac en tissu et j'achète moins de plastique.", 'stofftasche,plastik,benutze,kaufe'),
    ('Météo et nature', 'Wie viel Wasser hast du gestern getrunken?', "Combien d'eau as-tu bu hier ?", 'Gestern habe ich ungefähr zwei Liter Wasser getrunken, weil es sehr heiß war.', "Hier, j'ai bu environ deux litres d'eau, parce qu'il faisait très chaud.", 'wasser,liter,getrunken'),
    ('Météo et nature', 'Woher bekommst du dein Wasser zu Hause?', "D'où vient l'eau que tu as à la maison ?", 'Wir bekommen unser Wasser aus der Leitung. Manchmal holen wir es auch vom Brunnen.', 'Nous recevons notre eau du robinet. Parfois, nous allons aussi la chercher au puits.', 'wasser,leitung,brunnen'),
    ('Météo et nature', 'Wofür brauchst du Wasser am meisten?', "Pour quoi as-tu le plus besoin d'eau ?", 'Ich brauche Wasser am meisten zum Kochen, Waschen und Duschen.', "J'ai surtout besoin d'eau pour cuisiner, laver et me doucher.", 'wasser,kochen,waschen,duschen'),
    ('Météo et nature', 'Wo gehst du gern schwimmen?', 'Où aimes-tu aller nager ?', 'Ich gehe gern in einem Schwimmbad schwimmen, weil das Wasser dort sauber ist.', "J'aime aller nager dans une piscine, parce que l'eau y est propre.", 'schwimmen,schwimmbad,sauber'),
    ('Météo et nature', 'Wann warst du das letzte Mal an einem Fluss oder See?', 'Quand as-tu été pour la dernière fois à une rivière ou à un lac ?', 'Letzten Monat war ich mit Freunden an einem Fluss. Wir haben dort gegrillt.', "Le mois dernier, j'étais avec des amis au bord d'une rivière. Nous y avons fait un barbecue.", 'fluss,freunden,gegrillt'),
    ('Météo et nature', 'Isst du gern Mangos direkt vom Baum?', "Aimes-tu manger des mangues directement de l'arbre ?", 'Ja, ich esse gern Mangos direkt vom Baum. Sie sind süß und saftig.', "Oui, j'aime manger des mangues directement de l'arbre. Elles sont sucrées et juteuses.", 'mangos,baum,süß'),
    ('Météo et nature', 'Was wächst auf den Feldern in deiner Heimat?', "Qu'est-ce qui pousse dans les champs de ton pays ?", 'Auf den Feldern in meiner Heimat wachsen Maniok, Mais und Kochbananen.', 'Dans les champs de mon pays, il pousse du manioc, du maïs et des plantains.', 'feldern,maniok,mais,wachsen'),
    ('Météo et nature', 'Was ist deine schönste Erinnerung an die Natur?', 'Quel est ton plus beau souvenir de la nature ?', 'Meine schönste Erinnerung ist ein Ausflug zu den Lobé-Wasserfällen bei Kribi.', 'Mon plus beau souvenir est une excursion aux chutes de la Lobé près de Kribi.', 'erinnerung,ausflug,wasserfälle'),
    ('Météo et nature', 'Bist du schon einmal gewandert?', 'As-tu déjà fait de la randonnée ?', 'Ja, ich bin einmal auf einen Hügel bei Yaoundé gewandert. Die Aussicht war toll.', "Oui, j'ai fait une fois une randonnée sur une colline près de Yaoundé. La vue était super.", 'gewandert,aussicht,hügel'),
    ('Météo et nature', 'Welchen Nationalpark möchtest du gern besuchen?', 'Quel parc national aimerais-tu visiter ?', 'Ich möchte gern den Waza-Nationalpark besuchen, weil man dort Giraffen und Antilopen sieht.', "J'aimerais visiter le parc national de Waza, parce qu'on y voit des girafes et des antilopes.", 'nationalpark,besuchen,giraffen,antilopen'),
    ('Météo et nature', 'Du machst eine Wanderung. Was nimmst du mit?', "Tu fais une randonnée. Qu'emportes-tu ?", 'Ich nehme Wasser, etwas zu essen, eine Mütze und gute Schuhe mit.', "J'emporte de l'eau, quelque chose à manger, une casquette et de bonnes chaussures.", 'wasser,mütze,schuhe,nehme'),
    ('Météo et nature', 'Hast du als Kind einmal in einem Zelt geschlafen?', 'As-tu déjà dormi sous une tente quand tu étais enfant ?', 'Nein, ich habe noch nie in einem Zelt geschlafen. Aber ich würde es gern probieren.', "Non, je n'ai encore jamais dormi sous une tente. Mais j'aimerais bien essayer.", 'zelt,geschlafen,probieren'),
    ('Météo et nature', 'Wo machst du gern ein Picknick?', 'Où aimes-tu faire un pique-nique ?', 'Ich mache gern ein Picknick im Park oder am Fluss, am liebsten am Sonntag.', "J'aime faire un pique-nique au parc ou à la rivière, de préférence le dimanche.", 'picknick,park,fluss,sonntag'),
    ('Météo et nature', 'Beschreibe einen Park oder Garten in deiner Stadt.', 'Décris un parc ou un jardin de ta ville.', 'In meiner Stadt gibt es einen großen Park. Dort sind viele Bäume, Blumen und Bänke.', "Dans ma ville, il y a un grand parc. Il y a beaucoup d'arbres, de fleurs et de bancs.", 'park,bäume,blumen,bänke'),
    ('Météo et nature', 'Beschreibe das Wetter in deiner Stadt im Dezember.', "Décris le temps qu'il fait dans ta ville en décembre.", 'Im Dezember ist es in meiner Stadt trocken und warm. Morgens ist es manchmal ein bisschen kühl.', 'En décembre, il fait sec et chaud dans ma ville. Le matin, il fait parfois un peu frais.', 'dezember,trocken,warm,kühl'),
    ('Météo et nature', 'Du bist draußen und es ist sehr heiß. Was machst du?', 'Tu es dehors et il fait très chaud. Que fais-tu ?', 'Ich suche einen Platz im Schatten und trinke viel kaltes Wasser.', "Je cherche un endroit à l'ombre et je bois beaucoup d'eau fraîche.", 'schatten,wasser,trinke,platz'),
    ('Météo et nature', 'Wie fühlst du dich, wenn es regnet?', 'Comment te sens-tu quand il pleut ?', 'Wenn es regnet, bin ich ruhig und schlafe gern lange.', "Quand il pleut, je suis calme et j'aime dormir longtemps.", 'regnet,ruhig,schlafe'),
    ('Météo et nature', 'Ist es heute windig?', "Y a-t-il du vent aujourd'hui ?", 'Ja, heute ist es windig. Der Wind bewegt die Blätter der Bäume.', "Oui, il y a du vent aujourd'hui. Le vent fait bouger les feuilles des arbres.", 'windig,wind,blätter'),
    ('Météo et nature', 'Wie war das Wetter am Wochenende?', 'Quel temps faisait-il ce week-end ?', 'Am Wochenende war das Wetter nicht gut. Es war bewölkt und hat ein bisschen geregnet.', "Ce week-end, le temps n'était pas bon. Il était nuageux et il a un peu plu.", 'wetter,wochenende,geregnet,bewölkt'),
    ('Météo et nature', 'Was machst du gegen Mücken?', 'Que fais-tu contre les moustiques ?', 'Ich schlafe unter einem Moskitonetz, damit mich keine Mücken stechen.', 'Je dors sous une moustiquaire pour que les moustiques ne me piquent pas.', 'mücken,moskitonetz,schlafe'),
    ('Météo et nature', 'Welche Insekten magst du nicht?', "Quels insectes n'aimes-tu pas ?", 'Ich mag Kakerlaken nicht, weil sie schmutzig sind. Auch Fliegen finde ich nervig.', "Je n'aime pas les cafards, parce qu'ils sont sales. Je trouve aussi les mouches énervantes.", 'kakerlaken,fliegen,mag,schmutzig'),
    ('Météo et nature', 'Was hörst du morgens, wenn du aufwachst?', "Qu'entends-tu le matin quand tu te réveilles ?", 'Morgens höre ich Vögel singen und manchmal einen Hahn.', "Le matin, j'entends des oiseaux chanter et parfois un coq.", 'vögel,singen,hahn,morgens'),
    ('Météo et nature', 'Welchen Fisch hast du zuletzt gegessen?', 'Quel poisson as-tu mangé en dernier ?', 'Zuletzt habe ich gegrillten Fisch mit Reis gegessen. Er war sehr frisch.', "Dernièrement, j'ai mangé du poisson grillé avec du riz. Il était très frais.", 'fisch,gegessen,gegrillten'),
    ('Météo et nature', 'Wo möchtest du später wohnen, in der Stadt oder auf dem Land?', 'Où voudrais-tu habiter plus tard, en ville ou à la campagne ?', 'Später möchte ich in der Stadt wohnen, aber ich möchte auch ein kleines Haus mit Garten haben.', 'Plus tard, je voudrais habiter en ville, mais je voudrais aussi avoir une petite maison avec un jardin.', 'später,stadt,wohnen,garten'),
    ('Météo et nature', 'Was findest du an der Natur besonders schön?', "Qu'est-ce que tu trouves particulièrement beau dans la nature ?", 'Ich finde die grünen Berge und die frische Luft besonders schön.', "Je trouve les montagnes vertes et l'air frais particulièrement beaux.", 'berge,luft,schön,grünen'),
    ('Météo et nature', 'Was ist dein Lieblingsplatz in der Natur?', 'Quel est ton endroit préféré dans la nature ?', 'Mein Lieblingsplatz ist der Garten meiner Großmutter, denn dort ist es ruhig und grün.', 'Mon endroit préféré est le jardin de ma grand-mère, car il y fait calme et vert.', 'lieblingsplatz,garten,ruhig,grün'),
    ('Météo et nature', 'Wie findest du das Klima in Kamerun?', 'Comment trouves-tu le climat au Cameroun ?', 'Ich finde das Klima in Kamerun angenehm, denn es ist nie sehr kalt.', 'Je trouve le climat du Cameroun agréable, car il ne fait jamais très froid.', 'klima,angenehm,kalt'),
    ('Météo et nature', 'Welche Stadt in Kamerun ist kühler als Douala?', 'Quelle ville du Cameroun est plus fraîche que Douala ?', 'Ich glaube, Bamenda ist kühler als Douala, weil die Stadt höher liegt.', 'Je crois que Bamenda est plus fraîche que Douala, parce que la ville est plus haute.', 'bamenda,kühler,douala,höher'),
    ('Météo et nature', 'Was hast du in der letzten Trockenzeit gemacht?', "Qu'as-tu fait pendant la dernière saison sèche ?", 'In der letzten Trockenzeit bin ich zu meiner Familie ins Dorf gefahren und habe auf dem Feld geholfen.', "Pendant la dernière saison sèche, je suis allé voir ma famille au village et j'ai aidé dans les champs.", 'trockenzeit,dorf,gefahren,familie'),
    ('Météo et nature', 'Hast du schon einmal eine Überschwemmung erlebt?', 'As-tu déjà vécu une inondation ?', 'Nein, ich habe noch nie eine Überschwemmung erlebt, aber ich habe sie im Fernsehen gesehen.', "Non, je n'ai encore jamais vécu d'inondation, mais j'en ai vu à la télévision.", 'überschwemmung,erlebt,fernsehen'),
    ('Météo et nature', 'Du siehst am Himmel dunkle Wolken. Was machst du?', 'Tu vois de sombres nuages dans le ciel. Que fais-tu ?', 'Ich gehe schnell nach Hause, weil bald ein Gewitter kommt.', "Je rentre vite à la maison, parce qu'un orage arrive bientôt.", 'gewitter,schnell,hause,bald'),
    ('Météo et nature', 'Hast du schon einmal einen Baum gepflanzt?', 'As-tu déjà planté un arbre ?', 'Ja, in der Schule habe ich einmal einen kleinen Baum gepflanzt. Er ist jetzt groß.', "Oui, à l'école, j'ai planté une fois un petit arbre. Il est grand maintenant.", 'baum,gepflanzt,schule,groß'),
    ('Météo et nature', 'Was findest du besser für Fußball: Sonne oder Regen?', 'Que trouves-tu mieux pour le football : le soleil ou la pluie ?', 'Ich finde Regen besser für Fußball, weil man dann nicht so schnell müde wird.', "Je trouve la pluie mieux pour le football, parce qu'on se fatigue moins vite.", 'fußball,regen,besser,müde'),
    ('Météo et nature', 'Wo trocknest du deine Wäsche, wenn es regnet?', 'Où fais-tu sécher ton linge quand il pleut ?', 'Wenn es regnet, trockne ich meine Wäsche im Haus. Bei Sonne hänge ich sie draußen auf.', "Quand il pleut, je fais sécher mon linge dans la maison. Quand il y a du soleil, je l'étends dehors.", 'wäsche,regnet,draußen,trockne'),
    ('Météo et nature', 'Was isst oder trinkst du gern, wenn es sehr heiß ist?', "Qu'aimes-tu manger ou boire quand il fait très chaud ?", 'Wenn es heiß ist, esse ich gern Wassermelone und trinke kalten Saft.', "Quand il fait chaud, j'aime manger de la pastèque et boire du jus frais.", 'heiß,wassermelone,saft'),
    ('Météo et nature', 'Welche Kleidung brauchst du für eine Reise nach Deutschland im Winter?', 'De quels vêtements as-tu besoin pour un voyage en Allemagne en hiver ?', 'Ich brauche eine dicke Jacke, eine Mütze, Handschuhe und warme Schuhe.', "J'ai besoin d'une grosse veste, d'un bonnet, de gants et de chaussures chaudes.", 'jacke,mütze,handschuhe,warme'),
    ('Météo et nature', 'Hast du vom Klimawandel schon gehört?', 'As-tu déjà entendu parler du changement climatique ?', 'Ja, ich habe davon gehört. Es wird auf der Erde immer wärmer, und das ist ein Problem.', "Oui, j'en ai entendu parler. Il fait de plus en plus chaud sur la Terre, et c'est un problème.", 'gehört,wärmer,erde,problem'),
    ('Météo et nature', 'Was möchtest du in der Natur einmal erleben?', 'Que voudrais-tu vivre une fois dans la nature ?', 'Ich möchte einmal im Regenwald wandern und viele Tiere sehen.', "J'aimerais une fois faire une randonnée dans la forêt tropicale et voir beaucoup d'animaux.", 'regenwald,wandern,tiere'),
    ('Journée et temps', 'Wann stehst du normalerweise auf?', 'Quand te lèves-tu normalement ?', 'Normalerweise stehe ich um sechs Uhr auf.', 'Normalement, je me lève à six heures.', 'stehe,sechs,uhr'),
    ('Journée et temps', 'Wie spät ist es jetzt?', 'Quelle heure est-il maintenant ?', 'Es ist jetzt halb vier am Nachmittag.', "Il est maintenant trois heures et demie de l'après-midi.", 'halb,vier,nachmittag'),
    ('Journée et temps', 'Was machst du gleich nach dem Aufstehen?', "Que fais-tu juste après t'être levé ?", 'Nach dem Aufstehen wasche ich mir das Gesicht und putze die Zähne.', "Après m'être levé, je me lave le visage et je me brosse les dents.", 'aufstehen,gesicht,zähne'),
    ('Journée et temps', 'Frühstückst du jeden Tag?', 'Prends-tu le petit-déjeuner tous les jours ?', 'Ja, ich frühstücke jeden Tag, aber manchmal nur schnell.', 'Oui, je prends le petit-déjeuner tous les jours, mais parfois seulement rapidement.', 'frühstücke,jeden,schnell'),
    ('Journée et temps', 'Wie lange brauchst du morgens im Bad?', 'Combien de temps te faut-il le matin dans la salle de bain ?', 'Morgens brauche ich ungefähr zwanzig Minuten im Bad.', 'Le matin, il me faut environ vingt minutes dans la salle de bain.', 'brauche,minuten,bad'),
    ('Journée et temps', 'Welcher Wochentag gefällt dir am besten?', 'Quel jour de la semaine préfères-tu ?', 'Am besten gefällt mir der Samstag, weil ich dann frei habe.', "Ce que je préfère, c'est le samedi, parce que je suis libre ce jour-là.", 'samstag,gefällt,frei'),
    ('Journée et temps', 'Welcher Tag ist heute?', "Quel jour sommes-nous aujourd'hui ?", 'Heute ist Dienstag, und morgen ist Mittwoch.', "Aujourd'hui, c'est mardi, et demain c'est mercredi.", 'heute,dienstag,mittwoch'),
    ('Journée et temps', 'Was unternimmst du gern am Wochenende?', "Qu'aimes-tu faire le week-end ?", 'Am Wochenende besuche ich gern meine Familie und gehe mit Freunden spazieren.', "Le week-end, j'aime rendre visite à ma famille et me promener avec des amis.", 'wochenende,besuche,familie,spazieren'),
    ('Journée et temps', 'Wann gehst du abends ins Bett?', 'Quand vas-tu te coucher le soir ?', 'Abends gehe ich gegen zehn Uhr ins Bett.', 'Le soir, je vais me coucher vers dix heures.', 'bett,zehn,abends'),
    ('Journée et temps', 'Findest du die Woche zu kurz oder zu lang?', 'Trouves-tu la semaine trop courte ou trop longue ?', 'Ich finde die Woche zu kurz, denn das Wochenende vergeht so schnell.', 'Je trouve la semaine trop courte, car le week-end passe si vite.', 'woche,kurz,wochenende'),
    ('Journée et temps', 'Welcher Monat ist jetzt?', 'Quel mois sommes-nous maintenant ?', 'Jetzt ist November, das ist der elfte Monat im Jahr.', "Maintenant, c'est novembre, c'est le onzième mois de l'année.", 'november,monat,elfte'),
    ('Journée et temps', 'Welche Jahreszeit magst du am liebsten?', 'Quelle saison préfères-tu ?', 'Am liebsten mag ich die Trockenzeit, weil es dann nicht so oft regnet.', "Ce que j'aime le plus, c'est la saison sèche, parce qu'il ne pleut pas aussi souvent.", 'trockenzeit,mag,regnet'),
    ('Journée et temps', 'Wann beginnt dein Arbeitstag oder dein Unterricht?', 'Quand commence ta journée de travail ou ton cours ?', 'Mein Unterricht beginnt um acht Uhr morgens.', 'Mon cours commence à huit heures du matin.', 'beginnt,unterricht,acht'),
    ('Journée et temps', 'Wie findest du die Abende in deiner Stadt?', 'Comment trouves-tu les soirées dans ta ville ?', 'Ich finde die Abende in Yaoundé schön, weil es dann kühler ist.', "Je trouve les soirées à Yaoundé agréables, parce qu'il fait plus frais.", 'abende,kühler,schön'),
    ('Journée et temps', 'Isst du mittags lieber warm oder kalt?', 'À midi, préfères-tu manger chaud ou froid ?', 'Mittags esse ich lieber warm, zum Beispiel Reis mit Soße.', 'À midi, je préfère manger chaud, par exemple du riz avec de la sauce.', 'mittags,warm,reis'),
    ('Journée et temps', 'Wann isst du zu Abend?', 'Quand dînes-tu ?', 'Ich esse meistens um acht Uhr zu Abend.', 'Je dîne généralement à huit heures.', 'abend,esse,acht'),
    ('Journée et temps', 'Um wie viel Uhr kommst du abends nach Hause?', 'À quelle heure rentres-tu chez toi le soir ?', 'Abends komme ich meistens erst um sieben Uhr nach Hause.', "Le soir, je ne rentre généralement qu'à sept heures.", 'komme,sieben,hause'),
    ('Journée et temps', 'Wie kommst du morgens zur Arbeit oder zur Schule?', "Comment vas-tu le matin au travail ou à l'école ?", 'Ich fahre mit dem Moto-Taxi, weil das schnell geht.', "Je vais en moto-taxi, parce que c'est rapide.", 'moto,taxi,fahre'),
    ('Journée et temps', 'Welches Datum haben wir heute?', "Quelle est la date aujourd'hui ?", 'Heute ist der neunte November.', "Aujourd'hui, c'est le neuf novembre.", 'heute,neunte,november'),
    ('Journée et temps', 'Wie war dein Tag heute?', "Comment s'est passée ta journée aujourd'hui ?", 'Mein Tag war sehr lang, aber ich bin zufrieden.', 'Ma journée a été très longue, mais je suis satisfait.', 'tag,lang,zufrieden'),
    ('Journée et temps', 'Was findest du besser: früh schlafen gehen oder lange aufbleiben?', "Qu'est-ce que tu trouves mieux : te coucher tôt ou veiller tard ?", 'Ich finde früh schlafen gehen besser, weil ich dann am Morgen fit bin.', 'Je trouve mieux de me coucher tôt, parce que je suis alors en forme le matin.', 'besser,früh,fit'),
    ('Journée et temps', 'Wann klingelt dein Wecker?', 'Quand ton réveil sonne-t-il ?', 'Mein Wecker klingelt um halb sechs.', 'Mon réveil sonne à cinq heures et demie.', 'wecker,klingelt,halb'),
    ('Journée et temps', 'Was trinkst du morgens zuerst?', 'Que bois-tu en premier le matin ?', 'Morgens trinke ich zuerst ein Glas Wasser.', "Le matin, je bois d'abord un verre d'eau.", 'trinke,wasser,zuerst'),
    ('Journée et temps', 'Bist du ein Morgenmensch oder ein Abendmensch?', 'Es-tu plutôt du matin ou du soir ?', 'Ich bin eher ein Abendmensch, denn abends habe ich die meiste Energie.', "Je suis plutôt du soir, car c'est le soir que j'ai le plus d'énergie.", 'abendmensch,abends,energie'),
    ('Journée et temps', 'Wann wird es abends dunkel?', 'Quand fait-il nuit le soir ?', 'In Yaoundé wird es abends schon gegen sechs Uhr dunkel.', 'À Yaoundé, il fait déjà nuit vers six heures du soir.', 'dunkel,abends,sechs'),
    ('Journée et temps', 'Dein Freund fragt: Hast du heute Abend Zeit? Was antwortest du?', 'Ton ami demande : As-tu du temps ce soir ? Que réponds-tu ?', 'Ich antworte: Ja, gern! Ab acht Uhr habe ich Zeit.', "Je réponds : Oui, avec plaisir ! À partir de huit heures, j'ai le temps.", 'zeit,acht,antworte'),
    ('Journée et temps', 'Wo hast du dich zuletzt mit Freunden getroffen?', 'Où as-tu retrouvé des amis la dernière fois ?', 'Zuletzt habe ich mich mit Freunden in einem Restaurant in Bastos getroffen.', "La dernière fois, j'ai retrouvé des amis dans un restaurant à Bastos.", 'getroffen,freunden,restaurant'),
    ('Journée et temps', 'Wann machst du deine Mittagspause?', 'Quand fais-tu ta pause de midi ?', 'Meine Mittagspause ist um zwölf Uhr und dauert eine Stunde.', 'Ma pause de midi est à midi et dure une heure.', 'mittagspause,zwölf,stunde'),
    ('Journée et temps', 'Was ziehst du an, wenn du zur Arbeit gehst?', 'Que mets-tu quand tu vas au travail ?', 'Zur Arbeit ziehe ich meistens ein Hemd und eine dunkle Hose an.', 'Pour aller au travail, je mets généralement une chemise et un pantalon foncé.', 'ziehe,hemd,hose'),
    ('Journée et temps', 'Welcher Tag ist dein freier Tag?', 'Quel est ton jour de repos ?', 'Mein freier Tag ist der Sonntag, dann schlafe ich lange.', 'Mon jour de repos est le dimanche, je dors longtemps ce jour-là.', 'frei,sonntag,schlafe'),
    ('Journée et temps', 'Wann hast du gestern zu Mittag gegessen?', 'Quand as-tu déjeuné hier ?', 'Gestern habe ich um ein Uhr zu Mittag gegessen.', "Hier, j'ai déjeuné à une heure.", 'gestern,gegessen,uhr'),
    ('Journée et temps', 'Was ist dein Lieblingsmonat im Jahr?', "Quel est ton mois préféré de l'année ?", 'Mein Lieblingsmonat ist Dezember, weil ich dann Ferien habe.', "Mon mois préféré est décembre, parce que j'ai alors des vacances.", 'lieblingsmonat,dezember,ferien'),
    ('Journée et temps', 'Wie verbringst du deinen Samstagabend meistens?', 'Comment passes-tu généralement ton samedi soir ?', 'Samstagabends gehe ich oft mit Freunden essen oder tanzen.', 'Le samedi soir, je sors souvent manger ou danser avec des amis.', 'samstagabend,freunden,tanzen'),
    ('Journée et temps', 'Wann warst du das letzte Mal auf dem Markt?', 'Quand es-tu allé au marché pour la dernière fois ?', 'Ich war letzten Donnerstag auf dem Markt und habe Tomaten gekauft.', "J'étais au marché jeudi dernier et j'ai acheté des tomates.", 'markt,donnerstag,gekauft'),
    ('Journée et temps', 'Wie oft kochst du in der Woche?', 'À quelle fréquence cuisines-tu dans la semaine ?', 'Ich koche dreimal in der Woche, an den anderen Tagen esse ich im Restaurant.', 'Je cuisine trois fois par semaine, les autres jours je mange au restaurant.', 'koche,dreimal,woche'),
    ('Journée et temps', 'Wer macht bei dir zu Hause die Wäsche?', 'Qui fait la lessive chez toi ?', 'Die Wäsche mache ich selbst, normalerweise am Sonntag.', 'La lessive, je la fais moi-même, normalement le dimanche.', 'wäsche,selbst,sonntag'),
    ('Journée et temps', 'Warum stehst du manchmal spät auf?', 'Pourquoi te lèves-tu parfois tard ?', 'Manchmal stehe ich spät auf, weil ich abends lange arbeite.', 'Parfois je me lève tard, parce que je travaille longtemps le soir.', 'spät,abends,arbeite'),
    ('Journée et temps', 'Was hast du heute Morgen gemacht?', "Qu'as-tu fait ce matin ?", 'Heute Morgen habe ich Tee getrunken und das Haus geputzt.', "Ce matin, j'ai bu du thé et nettoyé la maison.", 'morgen,getrunken,geputzt'),
    ('Journée et temps', 'Was gab es gestern Abend bei dir zum Essen?', "Qu'y avait-il à manger chez toi hier soir ?", 'Gestern Abend gab es Ndolé mit Plantains.', 'Hier soir, il y avait du ndolé avec des plantains.', 'ndolé,plantains,gab'),
    ('Journée et temps', 'Wie hast du das letzte Wochenende verbracht?', 'Comment as-tu passé le dernier week-end ?', 'Ich habe das Wochenende bei meiner Familie verbracht und viel geschlafen.', "J'ai passé le week-end chez ma famille et j'ai beaucoup dormi.", 'wochenende,verbracht,geschlafen'),
    ('Journée et temps', 'Hast du gestern etwas Schönes erlebt?', 'As-tu vécu quelque chose de beau hier ?', 'Ja, gestern habe ich einen alten Freund auf der Straße getroffen.', "Oui, hier j'ai rencontré un vieil ami dans la rue.", 'gestern,freund,getroffen'),
    ('Journée et temps', 'Wie wichtig ist dir Pünktlichkeit?', 'Quelle importance a la ponctualité pour toi ?', 'Pünktlichkeit ist mir sehr wichtig, denn ich warte nicht gern.', "La ponctualité est très importante pour moi, car je n'aime pas attendre.", 'pünktlichkeit,wichtig,warte'),
    ('Journée et temps', 'Du kommst zehn Minuten zu spät. Was sagst du?', 'Tu arrives avec dix minutes de retard. Que dis-tu ?', 'Ich sage: Entschuldigung, es gab viel Verkehr. Es tut mir leid.', 'Je dis : Excusez-moi, il y avait beaucoup de circulation. Je suis désolé.', 'entschuldigung,leid,verkehr'),
    ('Journée et temps', 'Warum ist der Verkehr morgens in Douala so schlimm?', 'Pourquoi la circulation est-elle si mauvaise le matin à Douala ?', 'Morgens fahren viele Leute zur Arbeit, deshalb sind die Straßen voll.', "Le matin, beaucoup de gens vont au travail, c'est pourquoi les rues sont pleines.", 'arbeit,straßen,voll'),
    ('Journée et temps', 'Was möchtest du morgen machen?', 'Que voudrais-tu faire demain ?', 'Morgen möchte ich früh aufstehen und zum Markt gehen.', 'Demain, je voudrais me lever tôt et aller au marché.', 'morgen,möchte,markt'),
    ('Journée et temps', 'Wann hast du nächste Woche einen Termin?', 'Quand as-tu un rendez-vous la semaine prochaine ?', 'Am Dienstag habe ich einen Termin beim Zahnarzt.', "Mardi, j'ai un rendez-vous chez le dentiste.", 'termin,dienstag,zahnarzt'),
    ('Journée et temps', 'Du möchtest dich mit einem Freund verabreden. Was sagst du?', 'Tu veux fixer un rendez-vous avec un ami. Que dis-tu ?', 'Ich sage: Hast du am Samstag Zeit? Wir können einen Kaffee trinken.', 'Je dis : As-tu du temps samedi ? On peut boire un café.', 'zeit,samstag,kaffee'),
    ('Journée et temps', 'Wann können wir uns diese Woche treffen?', 'Quand pouvons-nous nous voir cette semaine ?', 'Ich habe am Mittwoch nach der Arbeit Zeit. Passt dir das?', "J'ai du temps mercredi après le travail. Est-ce que ça te convient ?", 'mittwoch,zeit,passt'),
    ('Journée et temps', 'Wie sagst du einen Termin ab?', 'Comment annules-tu un rendez-vous ?', 'Ich schreibe eine kurze Nachricht und sage, dass ich leider nicht kommen kann.', "J'écris un petit message et je dis que malheureusement je ne peux pas venir.", 'nachricht,leider,kommen'),
    ('Journée et temps', 'Wie lange hast du heute für deinen Weg gebraucht?', "Combien de temps as-tu mis aujourd'hui pour ton trajet ?", 'Heute habe ich nur fünfzehn Minuten gebraucht, weil ich zu Fuß gegangen bin.', "Aujourd'hui, je n'ai mis que quinze minutes, parce que j'y suis allé à pied.", 'gebraucht,minuten,fuß'),
    ('Journée et temps', 'Wie sieht deine Morgenroutine aus?', 'À quoi ressemble ta routine du matin ?', 'Zuerst dusche ich, dann frühstücke ich und lese die Nachrichten.', "D'abord je me douche, puis je prends mon petit-déjeuner et je lis les nouvelles.", 'zuerst,dusche,frühstücke,nachrichten'),
    ('Journée et temps', 'Was machst du abends, wenn du nicht arbeiten musst?', "Que fais-tu le soir quand tu n'as pas à travailler ?", 'Dann sehe ich fern oder telefoniere mit meiner Familie.', 'Alors je regarde la télé ou je téléphone à ma famille.', 'fern,telefoniere,familie'),
    ('Journée et temps', 'Was hast du gestern vor dem Schlafen gemacht?', "Qu'as-tu fait hier avant de dormir ?", 'Gestern habe ich vor dem Schlafen noch eine Serie angeschaut.', "Hier, avant de dormir, j'ai encore regardé une série.", 'schlafen,serie,angeschaut'),
    ('Journée et temps', 'Wie viel Zeit hast du pro Tag für dein Hobby?', 'Combien de temps as-tu par jour pour ton loisir ?', 'Pro Tag habe ich etwa eine Stunde Zeit für mein Hobby, ich spiele Fußball.', "Par jour, j'ai environ une heure pour mon loisir, je joue au football.", 'stunde,hobby,fußball'),
    ('Journée et temps', 'Was hältst du davon, am Sonntag zu arbeiten?', 'Que penses-tu du fait de travailler le dimanche ?', 'Ich finde das nicht gut, denn der Sonntag ist für meine Familie.', 'Je ne trouve pas ça bien, car le dimanche est pour ma famille.', 'sonntag,familie'),
    ('Journée et temps', 'Wann machst du Sport?', 'Quand fais-tu du sport ?', 'Ich mache am liebsten abends Sport, wenn es nicht mehr so heiß ist.', 'Je préfère faire du sport le soir, quand il ne fait plus aussi chaud.', 'sport,abends,heiß'),
    ('Journée et temps', 'Wer hilft dir bei der Hausarbeit?', "Qui t'aide pour les tâches ménagères ?", 'Mein Bruder hilft mir oft beim Putzen und Abwaschen.', "Mon frère m'aide souvent pour le ménage et la vaisselle.", 'hilft,putzen,abwaschen'),
    ('Journée et temps', 'Welche Hausarbeit magst du nicht?', "Quelle tâche ménagère n'aimes-tu pas ?", 'Ich mag das Bügeln nicht, denn es dauert sehr lange.', "Je n'aime pas repasser, car ça prend très longtemps.", 'bügeln,mag,lange'),
    ('Journée et temps', 'Wie oft räumst du dein Zimmer auf?', 'À quelle fréquence ranges-tu ta chambre ?', 'Ich räume mein Zimmer jeden Samstag auf.', 'Je range ma chambre tous les samedis.', 'räume,zimmer,samstag'),
    ('Journée et temps', 'Hast du einen Plan für diese Woche?', 'As-tu un programme pour cette semaine ?', 'Ja, am Montag lerne ich Deutsch und am Mittwoch gehe ich zum Sport.', "Oui, lundi j'apprends l'allemand et mercredi je vais au sport.", 'lerne,deutsch,sport'),
    ('Journée et temps', 'Wie planst du deine Woche?', 'Comment organises-tu ta semaine ?', 'Ich schreibe jeden Sonntag eine Liste mit allen Aufgaben in mein Heft.', "Chaque dimanche, j'écris dans mon cahier une liste de toutes les tâches.", 'liste,aufgaben,schreibe'),
    ('Journée et temps', 'Benutzt du einen Kalender oder dein Handy für Termine?', 'Utilises-tu un calendrier ou ton téléphone pour tes rendez-vous ?', 'Ich benutze mein Handy, weil ich es immer dabei habe.', "J'utilise mon téléphone, parce que je l'ai toujours sur moi.", 'handy,benutze,dabei'),
    ('Journée et temps', 'Welcher Feiertag ist bei euch besonders schön?', 'Quel jour férié est particulièrement agréable chez vous ?', 'Der Nationalfeiertag am zwanzigsten Mai ist schön, denn dann haben wir frei.', 'La fête nationale du vingt mai est agréable, car nous sommes alors en congé.', 'feiertag,mai,frei'),
    ('Journée et temps', 'Was machst du an einem freien Feiertag?', 'Que fais-tu un jour férié ?', 'An einem Feiertag schlafe ich lange und esse mit meiner Familie.', 'Un jour férié, je dors longtemps et je mange avec ma famille.', 'feiertag,schlafe,familie'),
    ('Journée et temps', 'Wie feierst du normalerweise deinen Geburtstag?', "Comment fêtes-tu d'habitude ton anniversaire ?", 'Ich feiere mit meiner Familie und meinen Freunden, und es gibt einen großen Kuchen.', 'Je fête avec ma famille et mes amis, et il y a un grand gâteau.', 'feiere,kuchen,freunden'),
    ('Journée et temps', 'Hast du am Wochenende lange geschlafen?', 'As-tu dormi longtemps ce week-end ?', 'Ja, am Sonntag habe ich bis neun Uhr geschlafen.', "Oui, dimanche j'ai dormi jusqu'à neuf heures.", 'geschlafen,sonntag,neun'),
    ('Journée et temps', 'Was hast du letzten Samstag gemacht?', "Qu'as-tu fait samedi dernier ?", 'Letzten Samstag habe ich meine Tante besucht und Fußball gespielt.', "Samedi dernier, j'ai rendu visite à ma tante et j'ai joué au football.", 'samstag,besucht,gespielt'),
    ('Journée et temps', 'Erzähl mir von deinem typischen Tag.', 'Raconte-moi ta journée type.', 'Ich stehe um halb sieben auf und arbeite bis fünf Uhr. Am Abend koche ich und gehe früh schlafen.', "Je me lève à six heures et demie et je travaille jusqu'à cinq heures. Le soir, je cuisine et je me couche tôt.", 'stehe,arbeite,koche,abend'),
    ('Journée et temps', 'Erzähl mir von einem besonderen Tag in deinem Leben.', 'Raconte-moi un jour spécial dans ta vie.', 'Ein besonderer Tag war mein erster Arbeitstag. Ich war sehr nervös.', "Un jour spécial a été mon premier jour de travail. J'étais très nerveux.", 'besonderer,arbeitstag,nervös'),
    ('Journée et temps', 'Was würdest du mit einem freien Tag machen?', 'Que ferais-tu avec un jour libre ?', 'Ich würde nach Kribi fahren und am Strand entspannen.', "J'irais à Kribi et je me détendrais sur la plage.", 'würde,kribi,strand'),
    ('Journée et temps', 'Wie hat sich dein Alltag verändert, seit du Deutsch lernst?', "Comment ton quotidien a-t-il changé depuis que tu apprends l'allemand ?", 'Jetzt lerne ich jeden Abend eine Stunde Deutsch, das ist neu in meinem Alltag.', "Maintenant, j'apprends l'allemand une heure chaque soir, c'est nouveau dans mon quotidien.", 'alltag,lerne,abend'),
    ('Journée et temps', 'Was ist für dich die beste Tageszeit und warum?', 'Quel est pour toi le meilleur moment de la journée et pourquoi ?', 'Die beste Tageszeit ist für mich der frühe Morgen, weil es dann ruhig ist.', "Le meilleur moment de la journée pour moi, c'est le petit matin, parce qu'il y a alors du calme.", 'tageszeit,morgen,ruhig'),
    ('Journée et temps', 'Wann bist du am müdesten?', 'Quand es-tu le plus fatigué ?', 'Am Nachmittag bin ich am müdesten, besonders nach dem Mittagessen.', "L'après-midi, je suis le plus fatigué, surtout après le déjeuner.", 'müdesten,nachmittag,mittagessen'),
    ('Journée et temps', 'Wie verbringst du gern einen Regentag?', 'Comment aimes-tu passer une journée de pluie ?', 'An einem Regentag bleibe ich zu Hause, höre Musik und koche etwas Warmes.', "Un jour de pluie, je reste à la maison, j'écoute de la musique et je cuisine quelque chose de chaud.", 'regentag,musik,koche'),
    ('Journée et temps', 'Was war dein wichtigster Termin im letzten Monat?', 'Quel a été ton rendez-vous le plus important le mois dernier ?', 'Mein wichtigster Termin im letzten Monat war ein Gespräch mit meinem Chef.', 'Mon rendez-vous le plus important du mois dernier a été un entretien avec mon chef.', 'wichtigster,termin,gespräch'),
    ('Journée et temps', 'Wie war der letzte Monat für dich?', "Comment s'est passé le mois dernier pour toi ?", 'Der letzte Monat war stressig, denn ich hatte viel Arbeit und wenig Schlaf.', "Le mois dernier a été stressant, car j'avais beaucoup de travail et peu de sommeil.", 'monat,stressig,arbeit'),
    ('Journée et temps', 'Was sind deine Pläne für den nächsten Monat?', 'Quels sont tes projets pour le mois prochain ?', 'Im nächsten Monat möchte ich meine Prüfung machen und danach Urlaub nehmen.', 'Le mois prochain, je voudrais passer mon examen puis prendre des vacances.', 'monat,prüfung,urlaub'),
    ('Journée et temps', 'Wo möchtest du in einem Jahr sein?', 'Où voudrais-tu être dans un an ?', 'In einem Jahr möchte ich fließend Deutsch sprechen und eine neue Arbeit haben.', 'Dans un an, je voudrais parler couramment allemand et avoir un nouveau travail.', 'jahr,deutsch,sprechen'),
    ('Journée et temps', 'Wie findest du den Alltag in einer großen Stadt?', 'Comment trouves-tu le quotidien dans une grande ville ?', 'Ich finde den Alltag in Douala laut, aber auch spannend, weil immer etwas passiert.', "Je trouve le quotidien à Douala bruyant, mais aussi passionnant, parce qu'il se passe toujours quelque chose.", 'alltag,laut,spannend'),
    ('Journée et temps', 'Wie findest du den Montagmorgen?', 'Comment trouves-tu le lundi matin ?', 'Ich finde den Montagmorgen anstrengend, denn das Wochenende ist dann vorbei.', 'Je trouve le lundi matin fatigant, car le week-end est alors terminé.', 'montagmorgen,anstrengend,wochenende'),
    ('Journée et temps', 'Fällt es dir schwer, früh aufzustehen?', 'Est-ce difficile pour toi de te lever tôt ?', 'Ja, es fällt mir schwer, weil ich abends spät ins Bett gehe.', "Oui, c'est difficile pour moi, parce que je me couche tard le soir.", 'schwer,spät,bett'),
    ('Journée et temps', 'Was denkst du über Leute, die oft zu spät kommen?', 'Que penses-tu des gens qui arrivent souvent en retard ?', 'Ich finde das unhöflich, besonders wenn niemand eine Nachricht schickt.', "Je trouve ça impoli, surtout quand personne n'envoie de message.", 'unhöflich,nachricht'),
    ('Journée et temps', 'Was isst du an einem Feiertag am liebsten?', 'Que manges-tu de préférence un jour férié ?', 'An einem Feiertag esse ich am liebsten Poulet DG mit Reis.', 'Un jour férié, je mange de préférence du poulet DG avec du riz.', 'feiertag,poulet,esse'),
    ('Journée et temps', 'Wie sagt man 8:15 Uhr auf Deutsch?', 'Comment dit-on 8 h 15 en allemand ?', 'Ich sage: Es ist Viertel nach acht.', 'Je dis : Il est huit heures et quart.', 'viertel,nach,acht'),
    ('Journée et temps', 'Wann beginnt bei dir der Feierabend?', 'Quand commence ta fin de journée de travail ?', 'Mein Feierabend beginnt um fünf Uhr, dann gehe ich nach Hause.', 'Ma fin de journée commence à cinq heures, ensuite je rentre à la maison.', 'feierabend,fünf,uhr'),
    ('Journée et temps', 'Was gefällt dir an der Mittagspause?', "Qu'est-ce qui te plaît dans la pause de midi ?", 'Mir gefällt, dass ich mich in der Mittagspause ausruhen kann.', "J'aime pouvoir me reposer pendant la pause de midi.", 'mittagspause,ausruhen,gefällt'),
    ('Journée et temps', 'Wie schaffst du es, morgens pünktlich zu sein?', 'Comment réussis-tu à être ponctuel le matin ?', 'Ich stelle meinen Wecker früh und bereite abends schon meine Tasche vor.', 'Je mets mon réveil tôt et je prépare déjà mon sac le soir.', 'wecker,tasche,früh'),
    ('Journée et temps', 'Wie lange hast du gestern Deutsch gelernt?', "Combien de temps as-tu appris l'allemand hier ?", 'Gestern habe ich eine Stunde Deutsch gelernt, danach war ich müde.', "Hier, j'ai appris l'allemand pendant une heure, après j'étais fatigué.", 'stunde,deutsch,gelernt'),
    ('Journée et temps', 'Wann hörst du am liebsten Musik?', 'Quand écoutes-tu le plus volontiers de la musique ?', 'Am liebsten höre ich Musik beim Kochen, dann macht die Arbeit mehr Spaß.', 'Je préfère écouter de la musique en cuisinant, alors le travail est plus agréable.', 'musik,höre,kochen'),
    ('Journée et temps', 'Warum ist es wichtig, die Zeit gut zu planen?', 'Pourquoi est-il important de bien planifier son temps ?', 'Wenn ich meine Zeit gut plane, habe ich mehr Freizeit und weniger Stress.', "Quand je planifie bien mon temps, j'ai plus de temps libre et moins de stress.", 'zeit,plane,stress'),
    ('Journée et temps', 'Wie oft gehst du abends aus?', 'À quelle fréquence sors-tu le soir ?', 'Ich gehe etwa einmal pro Woche abends aus, meistens am Freitag.', 'Je sors environ une fois par semaine le soir, la plupart du temps le vendredi.', 'einmal,woche,freitag'),
    ('Fêtes, médias et opinions', 'Feierst du deinen Geburtstag gern?', 'Aimes-tu fêter ton anniversaire ?', 'Ja, ich feiere meinen Geburtstag gern, weil ich dann viele Freunde sehe.', "Oui, j'aime fêter mon anniversaire, parce que je vois alors beaucoup d'amis.", 'feiere,geburtstag,freunde'),
    ('Fêtes, médias et opinions', 'Was wünschst du dir zum Geburtstag?', 'Que souhaites-tu pour ton anniversaire ?', 'Ich wünsche mir ein neues Handy und ein Buch.', 'Je souhaite un nouveau portable et un livre.', 'wünsche,handy,buch'),
    ('Fêtes, médias et opinions', 'Wie hast du letztes Jahr deinen Geburtstag gefeiert?', "Comment as-tu fêté ton anniversaire l'année dernière ?", 'Ich habe mit meiner Familie zu Hause gefeiert. Wir haben Kuchen gegessen.', "J'ai fêté à la maison avec ma famille. Nous avons mangé du gâteau.", 'gefeiert,familie,kuchen'),
    ('Fêtes, médias et opinions', 'Wer hat dir zuletzt ein Geschenk gemacht?', "Qui t'a fait un cadeau récemment ?", 'Mein Bruder hat mir ein Geschenk gemacht. Es war ein schönes Hemd.', "Mon frère m'a fait un cadeau. C'était une belle chemise.", 'geschenk,bruder,hemd'),
    ('Fêtes, médias et opinions', 'Dein Freund hat Geburtstag. Was schenkst du ihm?', 'Ton ami a son anniversaire. Que lui offres-tu ?', 'Ich schenke ihm ein Fußballtrikot, weil er gern Fußball spielt.', "Je lui offre un maillot de football, parce qu'il aime jouer au football.", 'schenke,fußballtrikot,fußball'),
    ('Fêtes, médias et opinions', 'Welches Geschenk hat dich einmal sehr glücklich gemacht?', "Quel cadeau t'a déjà rendu très heureux ?", 'Mein Vater hat mir ein Fahrrad geschenkt. Ich war sehr glücklich.', "Mon père m'a offert un vélo. J'étais très heureux.", 'fahrrad,geschenkt,glücklich,vater'),
    ('Fêtes, médias et opinions', 'Warst du schon einmal auf einer Hochzeit?', 'As-tu déjà été à un mariage ?', 'Ja, ich war letztes Jahr auf der Hochzeit meiner Cousine in Douala.', "Oui, l'année dernière j'étais au mariage de ma cousine à Douala.", 'hochzeit,cousine,war'),
    ('Fêtes, médias et opinions', 'Was ist bei einer Hochzeit in Kamerun anders als in Deutschland?', "Qu'est-ce qui est différent dans un mariage au Cameroun par rapport à l'Allemagne ?", 'In Kamerun feiert man sehr groß. Es gibt viel Essen, Musik und Tanz.', 'Au Cameroun, on fait une très grande fête. Il y a beaucoup de nourriture, de musique et de danse.', 'kamerun,essen,musik,tanz'),
    ('Fêtes, médias et opinions', 'Was ziehst du auf einer Party an?', 'Que mets-tu pour une fête ?', 'Auf einer Party ziehe ich ein schönes Hemd und eine dunkle Hose an.', 'Pour une fête, je mets une belle chemise et un pantalon foncé.', 'party,hemd,hose,ziehe'),
    ('Fêtes, médias et opinions', 'Du bist auf einer Party und kennst niemanden. Was machst du?', 'Tu es à une fête et tu ne connais personne. Que fais-tu ?', 'Ich gehe zu einer Person, sage Hallo und stelle mich vor.', 'Je vais vers une personne, je dis bonjour et je me présente.', 'stelle,hallo,person'),
    ('Fêtes, médias et opinions', 'Feierst du Weihnachten?', 'Fêtes-tu Noël ?', 'Ja, ich feiere Weihnachten mit meiner Familie, und wir essen zusammen.', 'Oui, je fête Noël avec ma famille et nous mangeons ensemble.', 'weihnachten,familie,feiere'),
    ('Fêtes, médias et opinions', 'Wie feierst du Weihnachten in Kamerun?', 'Comment fêtes-tu Noël au Cameroun ?', 'Wir kochen viel, besuchen die Familie und tragen neue Kleider.', 'Nous cuisinons beaucoup, rendons visite à la famille et portons de nouveaux habits.', 'kochen,familie,kleider,neue'),
    ('Fêtes, médias et opinions', 'Was isst du an Weihnachten gern?', 'Que manges-tu volontiers à Noël ?', 'An Weihnachten esse ich gern Reis mit Hähnchen und trinke Limonade.', "À Noël, j'aime manger du riz avec du poulet et boire de la limonade.", 'weihnachten,reis,hähnchen,esse'),
    ('Fêtes, médias et opinions', 'Was machst du an Silvester?', 'Que fais-tu le 31 décembre au soir ?', 'An Silvester bleibe ich mit Freunden zu Hause, und wir warten auf Mitternacht.', 'Le 31 décembre, je reste à la maison avec des amis et nous attendons minuit.', 'silvester,freunden,mitternacht'),
    ('Fêtes, médias et opinions', 'Was ist dein Wunsch für das neue Jahr?', 'Quel est ton souhait pour la nouvelle année ?', 'Mein Wunsch für das neue Jahr ist, dass meine Familie gesund bleibt.', 'Mon souhait pour la nouvelle année est que ma famille reste en bonne santé.', 'wunsch,jahr,familie,gesund'),
    ('Fêtes, médias et opinions', 'Hast du gute Vorsätze für das neue Jahr?', 'As-tu de bonnes résolutions pour la nouvelle année ?', 'Ja, ich möchte mehr Deutsch lernen und jeden Tag Sport machen.', "Oui, je veux apprendre plus d'allemand et faire du sport tous les jours.", 'deutsch,lernen,sport,möchte'),
    ('Fêtes, médias et opinions', 'Wen lädst du zu deiner Party ein?', 'Qui invites-tu à ta fête ?', 'Ich lade meine Freunde und meine Nachbarn ein.', "J'invite mes amis et mes voisins.", 'lade,freunde,nachbarn'),
    ('Fêtes, médias et opinions', 'Was bringst du mit, wenn du eingeladen bist?', "Qu'apportes-tu quand tu es invité ?", 'Ich bringe oft Blumen oder einen Kuchen mit.', "J'apporte souvent des fleurs ou un gâteau.", 'bringe,blumen,kuchen'),
    ('Fêtes, médias et opinions', 'Hat dich jemand zu einer Feier eingeladen?', "Quelqu'un t'a-t-il invité à une fête ?", 'Ja, meine Kollegin hat mich zu ihrer Feier am Samstag eingeladen.', "Oui, ma collègue m'a invité à sa fête samedi.", 'kollegin,feier,eingeladen,samstag'),
    ('Fêtes, médias et opinions', 'Du bekommst eine Einladung, aber du hast keine Zeit. Was sagst du?', "Tu reçois une invitation, mais tu n'as pas le temps. Que dis-tu ?", 'Ich sage: Vielen Dank, aber leider habe ich keine Zeit.', "Je dis : merci beaucoup, mais malheureusement je n'ai pas le temps.", 'dank,leider,zeit'),
    ('Fêtes, médias et opinions', 'Wie oft benutzt du dein Handy am Tag?', 'À quelle fréquence utilises-tu ton portable dans la journée ?', 'Ich benutze mein Handy fast den ganzen Tag, ungefähr fünf Stunden.', "J'utilise mon portable presque toute la journée, environ cinq heures.", 'handy,stunden,benutze'),
    ('Fêtes, médias et opinions', 'Wofür brauchst du dein Handy am meisten?', 'Pour quoi as-tu le plus besoin de ton portable ?', 'Ich brauche mein Handy zum Telefonieren und für WhatsApp.', "J'ai besoin de mon portable pour téléphoner et pour WhatsApp.", 'telefonieren,whatsapp,brauche'),
    ('Fêtes, médias et opinions', 'Wann hast du dein Handy gekauft?', 'Quand as-tu acheté ton portable ?', 'Ich habe mein Handy vor zwei Jahren in Yaoundé gekauft.', "J'ai acheté mon portable il y a deux ans à Yaoundé.", 'handy,gekauft,yaoundé,zwei'),
    ('Fêtes, médias et opinions', 'Was machst du, wenn dein Handy kaputt ist?', 'Que fais-tu quand ton portable est cassé ?', 'Wenn mein Handy kaputt ist, bringe ich es zu einem Techniker auf dem Markt.', "Quand mon portable est cassé, je l'apporte à un technicien au marché.", 'kaputt,techniker,markt,bringe'),
    ('Fêtes, médias et opinions', 'Wofür benutzt du Mobile Money?', 'Pour quoi utilises-tu Mobile Money ?', 'Ich benutze Mobile Money, um Geld zu schicken und Strom zu bezahlen.', "J'utilise Mobile Money pour envoyer de l'argent et payer l'électricité.", 'mobile,geld,bezahlen,schicken'),
    ('Fêtes, médias et opinions', 'Warum ist eine Powerbank bei Stromausfall praktisch?', 'Pourquoi une batterie externe est-elle pratique en cas de coupure de courant ?', 'Mit einer Powerbank kann ich mein Handy laden, wenn der Strom weg ist.', "Avec une batterie externe, je peux charger mon portable quand il n'y a plus de courant.", 'powerbank,laden,strom'),
    ('Fêtes, médias et opinions', 'Wie oft gehst du ins Internet?', 'À quelle fréquence vas-tu sur Internet ?', 'Ich gehe jeden Tag ins Internet, meistens am Abend.', 'Je vais sur Internet tous les jours, le plus souvent le soir.', 'internet,jeden,abend'),
    ('Fêtes, médias et opinions', 'Wie ist das Internet in deiner Stadt?', 'Comment est Internet dans ta ville ?', 'Das Internet ist manchmal langsam, besonders wenn es regnet.', 'Internet est parfois lent, surtout quand il pleut.', 'internet,langsam,regnet'),
    ('Fêtes, médias et opinions', 'Was suchst du oft im Internet?', 'Que cherches-tu souvent sur Internet ?', 'Ich suche oft Rezepte und Videos, um Deutsch zu lernen.', "Je cherche souvent des recettes et des vidéos pour apprendre l'allemand.", 'suche,rezepte,videos,deutsch'),
    ('Fêtes, médias et opinions', 'Hast du WLAN zu Hause?', 'As-tu le wifi à la maison ?', 'Nein, ich habe kein WLAN. Ich benutze Daten auf dem Handy.', "Non, je n'ai pas le wifi. J'utilise les données de mon portable.", 'wlan,daten,handy,kein'),
    ('Fêtes, médias et opinions', 'Wie viel Geld gibst du im Monat für Internet aus?', "Combien d'argent dépenses-tu par mois pour Internet ?", 'Ich gebe ungefähr 5000 CFA im Monat für Internet aus.', 'Je dépense environ 5000 CFA par mois pour Internet.', 'cfa,monat,internet,gebe'),
    ('Fêtes, médias et opinions', 'Kaufst du lieber online ein oder auf dem Markt?', 'Préfères-tu acheter en ligne ou au marché ?', 'Ich kaufe lieber auf dem Markt, denn dort kann ich handeln.', 'Je préfère acheter au marché, parce que là-bas je peux marchander.', 'markt,handeln,kaufe'),
    ('Fêtes, médias et opinions', 'Welche sozialen Medien benutzt du?', 'Quels réseaux sociaux utilises-tu ?', 'Ich benutze Facebook, TikTok und WhatsApp.', "J'utilise Facebook, TikTok et WhatsApp.", 'facebook,tiktok,whatsapp,benutze'),
    ('Fêtes, médias et opinions', 'Postest du gern Fotos?', 'Aimes-tu publier des photos ?', 'Ja, ich poste gern Fotos von meinen Freunden und vom Essen.', "Oui, j'aime publier des photos de mes amis et de la nourriture.", 'poste,fotos,gern'),
    ('Fêtes, médias et opinions', 'Was gefällt dir an sozialen Medien?', "Qu'est-ce qui te plaît dans les réseaux sociaux ?", 'Mir gefällt, dass ich mit Freunden in anderen Ländern sprechen kann.', "Ce qui me plaît, c'est que je peux parler avec des amis dans d'autres pays.", 'gefällt,freunden,ländern'),
    ('Fêtes, médias et opinions', 'Was findest du schlecht an sozialen Medien?', "Qu'est-ce que tu trouves mauvais dans les réseaux sociaux ?", 'Ich finde es schlecht, dass man dort zu viel Zeit verbringt.', "Je trouve mauvais qu'on y passe trop de temps.", 'schlecht,zeit,finde'),
    ('Fêtes, médias et opinions', 'Warum benutzen so viele Leute WhatsApp?', 'Pourquoi autant de gens utilisent-ils WhatsApp ?', 'Viele Leute benutzen WhatsApp, weil es billig und einfach ist.', "Beaucoup de gens utilisent WhatsApp parce que c'est bon marché et simple.", 'whatsapp,billig,einfach'),
    ('Fêtes, médias et opinions', 'Mit wem schreibst du am meisten auf WhatsApp?', 'Avec qui écris-tu le plus sur WhatsApp ?', 'Ich schreibe am meisten mit meiner Schwester.', "J'écris le plus avec ma sœur.", 'schreibe,schwester,meisten'),
    ('Fêtes, médias et opinions', 'Schickst du lieber Sprachnachrichten oder Textnachrichten?', 'Préfères-tu envoyer des messages vocaux ou des messages écrits ?', 'Ich schicke lieber Sprachnachrichten, denn Tippen dauert lange.', 'Je préfère envoyer des messages vocaux, parce que taper prend du temps.', 'sprachnachrichten,schicke,tippen'),
    ('Fêtes, médias et opinions', 'Was hast du heute Morgen auf WhatsApp gelesen?', "Qu'as-tu lu ce matin sur WhatsApp ?", 'Ich habe eine Nachricht von meinem Freund gelesen. Wir spielen am Samstag Fußball.', "J'ai lu un message de mon ami. Nous jouons au football samedi.", 'nachricht,freund,gelesen'),
    ('Fêtes, médias et opinions', 'Siehst du jeden Tag die Nachrichten?', 'Regardes-tu les informations tous les jours ?', 'Nein, ich sehe die Nachrichten nur am Wochenende.', 'Non, je ne regarde les informations que le week-end.', 'nachrichten,wochenende,sehe'),
    ('Fêtes, médias et opinions', 'Liest du Nachrichten lieber im Internet oder in der Zeitung?', 'Préfères-tu lire les informations sur Internet ou dans le journal ?', 'Ich lese sie lieber im Internet, weil die Zeitung teuer ist.', 'Je les lis plutôt sur Internet, parce que le journal coûte cher.', 'internet,zeitung,lese'),
    ('Fêtes, médias et opinions', 'Welche Sendung im Radio hörst du gern?', 'Quelle émission de radio aimes-tu écouter ?', 'Im Radio höre ich gern die Musiksendung am Abend.', "À la radio, j'aime écouter l'émission de musique du soir.", 'radio,musik,höre'),
    ('Fêtes, médias et opinions', 'Wann hörst du Musik?', 'Quand écoutes-tu de la musique ?', 'Ich höre Musik, wenn ich koche oder im Taxi sitze.', "J'écoute de la musique quand je cuisine ou quand je suis dans un taxi.", 'musik,koche,taxi'),
    ('Fêtes, médias et opinions', 'Wer ist dein Lieblingssänger oder deine Lieblingssängerin?', 'Qui est ton chanteur ou ta chanteuse préféré(e) ?', 'Mein Lieblingssänger ist Fally Ipupa, weil seine Lieder so schön sind.', 'Mon chanteur préféré est Fally Ipupa, parce que ses chansons sont si belles.', 'lieblingssänger,lieder,schön'),
    ('Fêtes, médias et opinions', 'Hast du schon einmal ein Konzert besucht?', 'As-tu déjà assisté à un concert ?', 'Ja, ich habe in Yaoundé ein Konzert besucht. Es war sehr laut.', "Oui, j'ai assisté à un concert à Yaoundé. C'était très bruyant.", 'konzert,yaoundé,laut'),
    ('Fêtes, médias et opinions', 'Kannst du ein Instrument spielen?', "Sais-tu jouer d'un instrument ?", 'Ich kann ein bisschen Gitarre spielen.', 'Je sais jouer un peu de la guitare.', 'gitarre,spielen,kann'),
    ('Fêtes, médias et opinions', 'Was hast du gestern Abend im Fernsehen gesehen?', "Qu'as-tu regardé hier soir à la télévision ?", 'Ich habe einen Film gesehen. Er war sehr lustig.', "J'ai regardé un film. Il était très drôle.", 'film,gesehen,lustig'),
    ('Fêtes, médias et opinions', 'Siehst du viel fern?', 'Regardes-tu beaucoup la télévision ?', 'Nein, ich sehe nicht viel fern, vielleicht eine Stunde am Abend.', 'Non, je ne regarde pas beaucoup la télévision, peut-être une heure le soir.', 'fern,stunde,abend'),
    ('Fêtes, médias et opinions', 'Was ist deine Lieblingssendung im Fernsehen?', 'Quelle est ton émission de télévision préférée ?', 'Meine Lieblingssendung ist eine Serie über eine Familie.', 'Mon émission préférée est une série sur une famille.', 'lieblingssendung,serie,familie'),
    ('Fêtes, médias et opinions', 'Gehst du lieber ins Kino oder schaust du zu Hause Filme?', 'Préfères-tu aller au cinéma ou regarder des films à la maison ?', 'Ich schaue lieber zu Hause Filme, weil das billiger ist.', "Je préfère regarder des films à la maison, parce que c'est moins cher.", 'schaue,filme,hause,billiger'),
    ('Fêtes, médias et opinions', 'Welche Spiele schaust du gern im Fernsehen?', 'Quels matchs aimes-tu regarder à la télévision ?', 'Ich schaue gern die Spiele der Nationalmannschaft von Kamerun.', "J'aime regarder les matchs de l'équipe nationale du Cameroun.", 'spiele,nationalmannschaft,kamerun,schaue'),
    ('Fêtes, médias et opinions', 'Was findest du besser, ein Buch oder einen Film?', 'Que trouves-tu mieux, un livre ou un film ?', 'Ich finde Filme besser, weil man dann nicht so viel lesen muss.', "Je trouve les films mieux, parce qu'on n'a alors pas autant à lire.", 'filme,besser,finde'),
    ('Fêtes, médias et opinions', 'Was hältst du von Werbung im Fernsehen?', 'Que penses-tu de la publicité à la télévision ?', 'Ich finde Werbung langweilig, weil sie zu lang ist.', "Je trouve la publicité ennuyeuse, parce qu'elle est trop longue.", 'werbung,langweilig,finde'),
    ('Fêtes, médias et opinions', 'Findest du das Leben in der Stadt schöner als auf dem Land?', "Trouves-tu la vie en ville plus agréable qu'à la campagne ?", 'Ja, ich finde die Stadt schöner, weil es dort mehr Arbeit gibt.', "Oui, je trouve la ville plus belle, parce qu'il y a plus de travail.", 'stadt,schöner,arbeit'),
    ('Fêtes, médias et opinions', 'Was denkst du über Handys in der Schule?', "Que penses-tu des portables à l'école ?", 'Ich denke, Handys in der Schule sind nicht gut, weil man dann nicht aufpasst.', "Je pense que les portables à l'école ne sont pas bien, parce qu'on ne fait alors pas attention.", 'handys,schule,denke,aufpasst'),
    ('Fêtes, médias et opinions', 'Findest du Mode wichtig?', 'Trouves-tu la mode importante ?', 'Ja, ich finde Mode wichtig, denn schöne Kleider machen gute Laune.', 'Oui, je trouve la mode importante, car de beaux vêtements mettent de bonne humeur.', 'mode,kleider,wichtig'),
    ('Fêtes, médias et opinions', 'Würdest du lieber ohne Handy oder ohne Fernseher leben?', 'Préférerais-tu vivre sans portable ou sans télévision ?', 'Ich würde lieber ohne Fernseher leben, denn das Handy ist wichtiger für mich.', 'Je préférerais vivre sans télévision, car le portable est plus important pour moi.', 'würde,fernseher,handy'),
    ('Fêtes, médias et opinions', 'Was ist dein größter Traum?', 'Quel est ton plus grand rêve ?', 'Mein größter Traum ist, ein eigenes Geschäft zu haben.', "Mon plus grand rêve est d'avoir ma propre boutique.", 'traum,geschäft,eigenes'),
    ('Fêtes, médias et opinions', 'Welchen Beruf möchtest du später haben?', 'Quel métier voudrais-tu faire plus tard ?', 'Ich möchte später in einer Bank arbeiten, weil ich gern mit Zahlen arbeite.', "Plus tard, je voudrais travailler dans une banque, parce que j'aime travailler avec les chiffres.", 'bank,arbeiten,zahlen,möchte'),
    ('Fêtes, médias et opinions', 'Was würdest du machen, wenn du viel Geld hättest?', "Que ferais-tu si tu avais beaucoup d'argent ?", 'Ich würde ein Haus für meine Eltern kaufen.', "J'achèterais une maison pour mes parents.", 'würde,haus,eltern,kaufen'),
    ('Fêtes, médias et opinions', 'Wie stellst du dir dein Leben mit vierzig vor?', "Comment t'imagines-tu ta vie à quarante ans ?", 'Mit vierzig habe ich hoffentlich eine große Familie und eine gute Arbeit.', "À quarante ans, j'espère avoir une grande famille et un bon travail.", 'vierzig,familie,arbeit'),
    ('Fêtes, médias et opinions', 'Was machst du nächstes Wochenende?', 'Que fais-tu le week-end prochain ?', 'Am Wochenende besuche ich meine Oma, und wir kochen zusammen.', 'Ce week-end, je rends visite à ma grand-mère et nous cuisinons ensemble.', 'wochenende,besuche,oma'),
    ('Fêtes, médias et opinions', 'Was möchtest du dir als Nächstes kaufen?', "Que voudrais-tu t'acheter ensuite ?", 'Als Nächstes möchte ich mir einen Laptop kaufen, weil ich ihn für die Arbeit brauche.', "Ensuite, je voudrais m'acheter un ordinateur portable, parce que j'en ai besoin pour le travail.", 'laptop,kaufen,möchte'),
    ('Fêtes, médias et opinions', 'Was ist deine schönste Erinnerung aus der Kindheit?', "Quel est ton plus beau souvenir d'enfance ?", 'Meine schönste Erinnerung ist ein Ausflug mit meiner Familie zum Wasserfall.', 'Mon plus beau souvenir est une excursion avec ma famille à la cascade.', 'erinnerung,ausflug,wasserfall'),
    ('Fêtes, médias et opinions', 'Womit hast du als Kind gern gespielt?', 'Avec quoi aimais-tu jouer quand tu étais enfant ?', 'Ich habe als Kind gern mit meinen Freunden Fußball gespielt.', "Enfant, j'aimais jouer au football avec mes amis.", 'gespielt,freunden,fußball'),
    ('Fêtes, médias et opinions', 'Erinnerst du dich an deinen ersten Schultag?', "Te souviens-tu de ton premier jour d'école ?", 'Ja, ich erinnere mich gut. Ich war sehr nervös und habe geweint.', "Oui, je m'en souviens bien. J'étais très nerveux et j'ai pleuré.", 'erinnere,nervös,geweint'),
    ('Fêtes, médias et opinions', 'Welchen Urlaub hast du nie vergessen?', "Quelles vacances n'as-tu jamais oubliées ?", 'Ich habe den Urlaub in Kribi nie vergessen. Das Meer war wunderbar.', "Je n'ai jamais oublié les vacances à Kribi. La mer était merveilleuse.", 'urlaub,kribi,meer'),
    ('Fêtes, médias et opinions', 'Wer war dein Lieblingslehrer in der Schule?', "Qui était ton professeur préféré à l'école ?", 'Mein Lieblingslehrer war Herr Mbarga, weil er immer geduldig war.', "Mon professeur préféré était Monsieur Mbarga, parce qu'il était toujours patient.", 'lieblingslehrer,geduldig,herr'),
    ('Fêtes, médias et opinions', 'Was hast du früher oft am Wochenende gemacht?', 'Que faisais-tu souvent le week-end autrefois ?', 'Früher bin ich am Wochenende oft zu meinen Großeltern gefahren.', "Autrefois, j'allais souvent chez mes grands-parents le week-end.", 'früher,großeltern,gefahren'),
    ('Fêtes, médias et opinions', 'Was ist in Kamerun beim Essen anders als in Deutschland?', "Qu'est-ce qui est différent au Cameroun pour les repas par rapport à l'Allemagne ?", 'In Kamerun isst man oft mit den Händen, in Deutschland mit Messer und Gabel.', 'Au Cameroun, on mange souvent avec les mains, en Allemagne avec un couteau et une fourchette.', 'kamerun,händen,gabel,deutschland'),
    ('Fêtes, médias et opinions', 'Was ist in Kamerun am Sonntag typisch?', "Qu'est-ce qui est typique le dimanche au Cameroun ?", 'Am Sonntag kochen viele Familien zusammen und laden Gäste ein.', 'Le dimanche, beaucoup de familles cuisinent ensemble et invitent des gens.', 'sonntag,familien,kochen,gäste'),
    ('Fêtes, médias et opinions', 'Wie begrüßt man sich in Kamerun?', 'Comment se salue-t-on au Cameroun ?', 'Man gibt sich die Hand und fragt: Wie geht es der Familie?', 'On se serre la main et on demande : comment va la famille ?', 'hand,familie,fragt'),
    ('Fêtes, médias et opinions', 'Was ist in Deutschland anders als in Kamerun?', "Qu'est-ce qui est différent en Allemagne par rapport au Cameroun ?", 'In Deutschland sind die Leute sehr pünktlich, und das Wetter ist kälter.', 'En Allemagne, les gens sont très ponctuels et le temps est plus froid.', 'deutschland,pünktlich,wetter,kälter'),
    ('Fêtes, médias et opinions', 'Welche Tradition magst du in deiner Familie am liebsten?', 'Quelle tradition préfères-tu dans ta famille ?', 'Ich mag am liebsten, dass wir am Samstag alle zusammen Fufu essen.', "Ce que j'aime le plus, c'est que le samedi nous mangeons tous ensemble du fufu.", 'mag,samstag,fufu,zusammen'),
    ('Fêtes, médias et opinions', 'Trägst du manchmal traditionelle Kleidung?', 'Portes-tu parfois des vêtements traditionnels ?', 'Ja, bei großen Festen trage ich Kleidung aus buntem Stoff.', 'Oui, lors des grandes fêtes, je porte des vêtements en tissu coloré.', 'festen,kleidung,stoff,trage'),
    ('Fêtes, médias et opinions', 'Welches traditionelle Gericht kochst du am besten?', 'Quel plat traditionnel cuisines-tu le mieux ?', 'Ich koche am besten Ndolé mit Fisch und Kochbananen.', "Ce que je cuisine le mieux, c'est le ndolé avec du poisson et des plantains.", 'ndolé,koche,kochbananen'),
    ('Fêtes, médias et opinions', 'Was ist deine Lieblingsfarbe und warum?', 'Quelle est ta couleur préférée et pourquoi ?', 'Meine Lieblingsfarbe ist Blau, weil ich den Himmel schön finde.', 'Ma couleur préférée est le bleu, parce que je trouve le ciel beau.', 'lieblingsfarbe,blau,himmel'),
    ('Fêtes, médias et opinions', 'Welche Jahreszeit magst du lieber, die Regenzeit oder die Trockenzeit?', 'Quelle saison préfères-tu, la saison des pluies ou la saison sèche ?', 'Ich mag die Regenzeit am liebsten, weil dann alles grün ist.', "J'aime surtout la saison des pluies, parce que tout est alors vert.", 'regenzeit,grün,mag'),
    ('Fêtes, médias et opinions', 'Welcher Tag der Woche ist dein Lieblingstag?', 'Quel jour de la semaine est ton jour préféré ?', 'Mein Lieblingstag ist Freitag, weil dann das Wochenende anfängt.', 'Mon jour préféré est le vendredi, parce que le week-end commence alors.', 'lieblingstag,freitag,wochenende'),
    ('Fêtes, médias et opinions', 'Welches Tier magst du am liebsten?', 'Quel animal préfères-tu ?', 'Ich mag Katzen am liebsten, weil sie so ruhig sind.', "Ce que j'aime le plus, ce sont les chats, parce qu'ils sont si calmes.", 'katzen,mag,ruhig'),
    ('Fêtes, médias et opinions', 'Welchen Wunsch hast du für deinen besten Freund?', 'Quel souhait as-tu pour ton meilleur ami ?', 'Ich wünsche meinem besten Freund viel Erfolg bei der Arbeit.', 'Je souhaite à mon meilleur ami beaucoup de réussite au travail.', 'wünsche,freund,erfolg'),
    ('Fêtes, médias et opinions', 'Was ist gut an einem Taxi-Moto in Yaoundé?', "Qu'est-ce qui est bien dans un taxi-moto à Yaoundé ?", 'Ein Taxi-Moto ist schnell, auch wenn viel Verkehr ist.', 'Un taxi-moto est rapide, même quand il y a beaucoup de circulation.', 'taxi-moto,schnell,verkehr'),
    ('Fêtes, médias et opinions', 'Welche Vorteile hat ein Smartphone im Alltag?', 'Quels avantages un smartphone a-t-il au quotidien ?', 'Ich kann damit Fotos machen, Karten lesen und Musik hören.', 'Je peux faire des photos avec, lire des cartes et écouter de la musique.', 'fotos,karten,musik'),
    ('Fêtes, médias et opinions', 'Was ist besser, ein Fahrrad oder ein Auto?', "Qu'est-ce qui est mieux, un vélo ou une voiture ?", 'Ein Fahrrad ist billiger und gesünder, aber ein Auto ist bequemer.', 'Un vélo est moins cher et plus sain, mais une voiture est plus confortable.', 'fahrrad,auto,billiger,bequemer'),
    ('Fêtes, médias et opinions', 'Welche Nachteile hat es, jeden Tag Fast Food zu essen?', 'Quels inconvénients y a-t-il à manger du fast-food tous les jours ?', 'Fast Food ist ungesund, und es kostet viel Geld.', "Le fast-food n'est pas sain et ça coûte cher.", 'fast,ungesund,geld'),
]

def seed_neferti_bank(cursor):
    """Synchronise la banque de questions (ajoute / met à jour / retire ce qui n'est plus dans le code)."""
    totals = {}
    for cat, *_ in NEFERTI_BANK:
        totals[cat] = totals.get(cat, 0) + 1
    seen_pos = {}
    wanted = {}
    for cat, q_de, q_fr, a_de, a_fr, kw in NEFERTI_BANK:
        pos = seen_pos.get(cat, 0)
        seen_pos[cat] = pos + 1
        frac = pos / max(1, totals[cat])
        lvl = 1 if frac < 0.4 else (2 if frac < 0.8 else 3)
        wanted[q_de] = (cat, q_fr, a_de, a_fr, kw, lvl, pos)
    existing = {r[1]: r[0] for r in cursor.execute("SELECT id, q_de FROM neferti_bank").fetchall()}
    for q_de, (cat, q_fr, a_de, a_fr, kw, lvl, pos) in wanted.items():
        cursor.execute(
            """INSERT INTO neferti_bank(cat, q_de, q_fr, a_de, a_fr, kw, lvl, pos) VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(q_de) DO UPDATE SET cat=excluded.cat, q_fr=excluded.q_fr, a_de=excluded.a_de,
                 a_fr=excluded.a_fr, kw=excluded.kw, lvl=excluded.lvl, pos=excluded.pos
               WHERE cat!=excluded.cat OR q_fr!=excluded.q_fr OR a_de!=excluded.a_de OR a_fr!=excluded.a_fr
                  OR kw!=excluded.kw OR lvl!=excluded.lvl OR pos!=excluded.pos""",
            (cat, q_de, q_fr, a_de, a_fr, kw, lvl, pos))
    gone = [bid for q, bid in existing.items() if q not in wanted]
    for i in range(0, len(gone), 400):
        chunk = gone[i:i + 400]
        marks = ",".join("?" * len(chunk))
        cursor.execute("DELETE FROM neferti_bank WHERE id IN (%s)" % marks, chunk)
        cursor.execute("DELETE FROM neferti_asked WHERE bank_id IN (%s)" % marks, chunk)

# ---------------------------------------------------------
# SÉCURITÉ & DÉCORATEURS
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("Accès réservé à l'administrateur.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

def validate_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def validate_password(pwd):
    if len(pwd) < 8 or len(pwd) > 128: return False
    if not re.search(r'[A-Z]', pwd): return False
    if not re.search(r'[a-z]', pwd): return False
    if not re.search(r'[0-9]', pwd): return False
    return True

# ---------------------------------------------------------
# SÉCURITÉ v4.1 : limite de connexions, CSRF, rendu des pages
# ---------------------------------------------------------
LOGIN_MAX_FAILS = 8          # échecs max par (IP + email) sur la fenêtre
LOGIN_MAX_FAILS_MAIL = 30    # échecs max par email (toutes IP) sur la fenêtre
LOGIN_WINDOW = 900           # secondes (15 min)

def _client_ip():
    xf = request.headers.get("X-Forwarded-For", "")
    ip = xf.split(",")[-1].strip() if xf else (request.remote_addr or "")
    return ip or "?"

def _login_keys(ident):
    ident = (ident or "").strip().lower()
    k_ip = "ip|" + hashlib.sha1((_client_ip() + "|" + ident).encode("utf-8")).hexdigest()
    k_id = "id|" + hashlib.sha1(ident.encode("utf-8")).hexdigest()
    return k_ip, k_id

def _login_blocked(db, k_ip, k_id, strict=False):
    db.execute("DELETE FROM login_attempts WHERE ts < ?", (time.time() - LOGIN_WINDOW,))
    n_ip = db.execute("SELECT COUNT(*) FROM login_attempts WHERE k=?", (k_ip,)).fetchone()[0]
    n_id = db.execute("SELECT COUNT(*) FROM login_attempts WHERE k=?", (k_id,)).fetchone()[0]
    # le compte administrateur est protégé plus sévèrement
    return n_ip >= (5 if strict else LOGIN_MAX_FAILS) or n_id >= (20 if strict else LOGIN_MAX_FAILS_MAIL)

def _login_fail(db, k_ip, k_id):
    now = time.time()
    db.execute("INSERT INTO login_attempts(k, ts) VALUES(?,?)", (k_ip, now))
    db.execute("INSERT INTO login_attempts(k, ts) VALUES(?,?)", (k_id, now))
    db.commit()

def _login_ok(db, k_ip):
    db.execute("DELETE FROM login_attempts WHERE k=?", (k_ip,))
    db.commit()

def csrf_token():
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_hex(16)
        session["_csrf"] = tok
    return tok

_FORM_POST_RE = re.compile(r'(<form\b[^>]*\bmethod\s*=\s*["\']post["\'][^>]*>)', re.I)

def page(html):
    """Renvoie la page TELLE QUELLE (jamais interprétée par Jinja : plus d'injection de
    template) et ajoute le jeton CSRF dans chaque formulaire POST."""
    hidden = '<input type="hidden" name="csrf_token" value="%s">' % csrf_token()
    return _FORM_POST_RE.sub(lambda m: m.group(1) + hidden, html)

@app.before_request
def _csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    good = session.get("_csrf", "")
    if good and sent and hmac.compare_digest(str(sent), str(good)):
        return None
    if request.is_json or request.path.startswith("/neferti/"):
        return jsonify({"error": "Session expirée. Recharge la page."}), 400
    flash("Session expirée, réessaie.", "warning")
    ref = request.referrer or ""
    if ref and urlparse(ref).netloc == request.host:
        return redirect(ref)
    return redirect(url_for("index"))

# Politique de sécurité du contenu : le navigateur refuse tout script/ressource venant d'ailleurs.
_CSP = ("default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "media-src 'self' blob: data:; "
        "connect-src 'self'; "
        "font-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'")

@app.after_request
def _security_headers(resp):
    h_ = resp.headers
    h_.setdefault("X-Content-Type-Options", "nosniff")
    h_.setdefault("X-Frame-Options", "SAMEORIGIN")
    h_.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h_.setdefault("Content-Security-Policy", _CSP)
    h_.setdefault("Permissions-Policy", "camera=(), geolocation=(), payment=(), usb=(), microphone=(self)")
    h_.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    h_.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https":
        h_.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    # Pages privées : jamais gardées en cache (le bouton « retour » ne ré-affiche pas une page après déconnexion)
    if resp.mimetype == "text/html" and ("user_id" in session or request.path.startswith(("/admin", "/login", "/register", "/compte"))):
        h_["Cache-Control"] = "no-store, private"
        h_["Pragma"] = "no-cache"
    if request.path.startswith(("/admin", "/compte")):
        h_["X-Robots-Tag"] = "noindex, nofollow"
    h_["Server"] = "NATHO"
    return resp

@app.before_request
def _session_hardening():
    """Sessions limitées dans le temps ; un compte supprimé ou rétrogradé perd immédiatement ses droits."""
    if "user_id" not in session:
        return None
    session.permanent = True
    try:
        db = get_db()
        row = db.execute("SELECT is_admin FROM users WHERE id=?", (session["user_id"],)).fetchone()
    except Exception:
        return None
    if row is None:
        session.clear()
        return None
    session["is_admin"] = bool(row["is_admin"])
    return None

@app.route("/robots.txt")
def robots_txt():
    resp = make_response("User-agent: *\nDisallow: /admin\nDisallow: /compte\nDisallow: /neferti\nDisallow: /tts\n")
    resp.mimetype = "text/plain"
    return resp

# Pages d'erreur sobres : jamais de trace Python ni de détail technique côté visiteur
def _err_page(code, title, msg):
    body = f"""
    <div class="card" style="text-align:center;">
      <h1>{h(title)}</h1><p style="color:var(--muted);">{h(msg)}</p>
      <a class="btn" href="/">Retour à l'accueil</a>
    </div>"""
    try:
        html = page(layout(title, body, {"is_admin": bool(session.get("is_admin"))} if "user_id" in session else None))
    except Exception:
        html = "<h1>%s</h1><p>%s</p>" % (h(title), h(msg))
    return html, code

@app.errorhandler(404)
def _e404(e):
    return _err_page(404, "Page introuvable", "Cette page n'existe pas.")

@app.errorhandler(405)
def _e405(e):
    return _err_page(405, "Action non autorisée", "Cette action n'est pas permise ici.")

@app.errorhandler(413)
def _e413(e):
    return _err_page(413, "Envoi trop volumineux", "Les données envoyées sont trop grandes.")

@app.errorhandler(500)
def _e500(e):
    return _err_page(500, "Oups, une erreur est survenue", "Réessaie dans un instant.")

# Limite de débit générique (en mémoire, par utilisateur) pour les API sensibles
_rate_hits = {}

def _rate_ok(bucket, ident, maxn, window):
    now = time.time()
    dq = _rate_hits.setdefault((bucket, ident), deque())
    while dq and dq[0] < now - window:
        dq.popleft()
    if len(dq) >= maxn:
        return False
    dq.append(now)
    if len(_rate_hits) > 5000:
        for k in [k for k, v in _rate_hits.items() if not v or v[-1] < now - 3600][:2000]:
            _rate_hits.pop(k, None)
    return True

# ---------------------------------------------------------
# DONNÉES DE PLAYLISTS (partagées par /playlists et les pages de contenu)
# ---------------------------------------------------------
def _json_for_script(obj):
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))

def playlist_data_script(payload):
    """Fusionne des playlists dans window.NATHO_PLAYLISTS (sans écraser les autres)."""
    return ("<script>(function(){var n=" + _json_for_script(payload) + ";"
            "var d=window.NATHO_PLAYLISTS=window.NATHO_PLAYLISTS||{};"
            "Object.keys(n).forEach(function(k){"
            "if(k==='order'){d.order=Object.assign(d.order||{},n.order);}else{d[k]=n[k];}"
            "});})();</script>")

def _speak_playlists(db):
    return {r["title"]: json.loads(r["items_json"]) for r in db.execute(
        "SELECT title, items_json FROM speak_playlists WHERE kind='speak' ORDER BY id").fetchall()}

def _essentials_playlists(db):
    return {r["title"]: json.loads(r["items_json"]) for r in db.execute(
        "SELECT title, items_json FROM speak_playlists WHERE kind='essentials' ORDER BY id").fetchall()}

def _nomakk_playlists(db):
    return {r["title"]: json.loads(r["items_json"]) for r in db.execute(
        "SELECT title, items_json FROM nomakk_playlist ORDER BY id").fetchall()}

def _dialogue_playlists(db):
    rows = db.execute("SELECT title, lines_json FROM dialogues ORDER BY id").fetchall()
    data = {}
    for r in rows:
        data[r["title"]] = [{"fr": l["fr"], "de": l["de"]} for l in json.loads(r["lines_json"])]
    return data, [r["title"] for r in rows]

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
def say_btn(label, mode, fr="", de="", css="btn", style=""):
    style_attr = f' style="{h(style, quote=True)}"' if style else ""
    return (f'<button type="button" class="{css}" data-say="{mode}" '
            f'data-fr="{h(fr, quote=True)}" data-de="{h(de, quote=True)}"{style_attr}>{label}</button>')

def playlist_btn(label, kind, key, css="btn"):
    return (f'<button type="button" class="{css}" data-say="playlist" '
            f'data-kind="{h(kind, quote=True)}" data-key="{h(key, quote=True)}">{label}</button>')

# =========================================================
# === NEFERTI : logique de comparaison (Levenshtein) ===
# =========================================================
def _levenshtein(a, b):
    a = a.lower().strip()
    b = b.lower().strip()
    if a == b: return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                          prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]

def _norm_text(s):
    s = (s or "").lower()
    s = re.sub(r"[^\w\säöüß]", " ", s)
    return re.sub(r"\s+", " ", s).strip()

def _lev_ratio(a, b):
    m = max(len(a), len(b), 1)
    return max(0.0, 1.0 - _levenshtein(a, b) / m)

def _best_window(part, heard):
    """Meilleure ressemblance (0..1) entre `part` et une portion de `heard`."""
    pw = part.split()
    hw = heard.split()
    if not pw or not hw:
        return 0.0
    n = len(pw)
    best = 0.0
    for size in {max(1, n - 1), n, n + 1}:
        for i in range(0, max(1, len(hw) - size + 1)):
            best = max(best, _lev_ratio(part, " ".join(hw[i:i + size])))
    return best

def _score_pronunciation(expected, heard):
    """Score 0-100. `expected` peut contenir des « ... » (parties personnelles, ignorées) et
    plusieurs variantes séparées par « / » : on garde la meilleure variante."""
    hd = _norm_text(heard)
    if not hd:
        return 0
    best = 0.0
    for variant in str(expected or "").split("/"):
        parts = [_norm_text(p) for p in variant.split("...")]
        parts = [p for p in parts if p]
        if not parts:
            continue
        if "..." in variant:
            s = sum(_best_window(p, hd) for p in parts) / len(parts)
        else:
            vv = _norm_text(variant)
            s = max(_lev_ratio(vv, hd), _best_window(vv, hd))
        best = max(best, s)
    return int(round(best * 100))

def _keyword_hit(keywords_csv, heard):
    toks = set(_norm_text(heard).split())
    return any(k.strip().lower() in toks for k in (keywords_csv or "").split(",") if k.strip())

def _build_correction(expected, heard, score):
    """Retourne une correction en français."""
    if score >= 85:
        return ""
    if score >= 60:
        return f"Presque ! Neferti a entendu « {heard} ». Modèle de phrase : « {expected} »."
    return (f"Ce n'est pas tout à fait ça. Neferti a entendu « {heard} », "
            f"mais le modèle attendu était « {expected} ». Réessaie en articulant bien.")

def _save_memory(user_id, key, value):
    if not key or not value:
        return
    db = get_db()
    db.execute(
        """INSERT INTO neferti_memory(user_id, mem_key, mem_value)
           VALUES(?,?,?)
           ON CONFLICT(user_id, mem_key) DO UPDATE SET
           mem_value=excluded.mem_value, updated_at=CURRENT_TIMESTAMP""",
        (user_id, key, value.strip()[:120])
    )
    db.commit()

def _get_memory(user_id):
    db = get_db()
    rows = db.execute(
        "SELECT mem_key, mem_value FROM neferti_memory WHERE user_id=?",
        (user_id,)
    ).fetchall()
    return {r["mem_key"]: r["mem_value"] for r in rows}

def _save_history(user_id, role, fr_text="", de_text="", heard_text="", score=0):
    db = get_db()
    db.execute(
        "INSERT INTO neferti_history(user_id, role, fr_text, de_text, heard_text, score) "
        "VALUES(?,?,?,?,?,?)",
        (user_id, role, fr_text[:400], de_text[:400], heard_text[:400], score)
    )
    db.commit()

def _get_scenario(step_key):
    db = get_db()
    return db.execute(
        "SELECT * FROM neferti_scenarios WHERE step_key=? LIMIT 1",
        (step_key,)
    ).fetchone()

def _scenario_exists(step_key):
    return _get_scenario(step_key) is not None

# ---------------------------------------------------------
# CSS & JS
# ---------------------------------------------------------
FAVICON_SVG = """data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%2387CEEB'/><path d='M30 65V45c0-15 10-25 20-25s20 10 20 25v20' stroke='white' stroke-width='8' fill='none' stroke-linecap='round'/><rect x='25' y='60' width='12' height='20' rx='4' fill='white'/><rect x='63' y='60' width='12' height='20' rx='4' fill='white'/><text x='50' y='58' font-family='Arial' font-size='28' font-weight='bold' fill='white' text-anchor='middle'>N</text></svg>"""

BASE_CSS = """
<style>
:root{
  --sky:#87CEEB; --sky-dark:#4AA5D0; --sky-light:#E8F6FD;
  --ink:#0F2A3F; --muted:#5B7A90; --white:#FFFFFF;
  --ok:#2ECC71; --warn:#F39C12; --danger:#E74C3C;
  --bg-gradient: linear-gradient(180deg,#E8F6FD 0%,#F7FCFE 100%);
  --card-bg: #FFFFFF;
  --nav-bg: #87CEEB;
  --sidebar-bg: #1a2a35;
  --input-bg: #fbfdff;
  --border-light: #EAF3F8;
}
html[data-theme="dark"]{
  --sky:#4AA5D0; --sky-dark:#2F8CBB; --sky-light:#1e3a4d;
  --ink:#E8F6FD; --muted:#9BB8C9; --white:#0F2A3F;
  --bg-gradient: linear-gradient(180deg,#0F2A3F 0%,#152F44 100%);
  --card-bg: #16304a;
  --nav-bg: #0d2233;
  --sidebar-bg: #071722;
  --input-bg: #1a3a52;
  --border-light: #1f4560;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;
     background:var(--bg-gradient);
     color:var(--ink);min-height:100vh; padding-bottom: 90px; margin-left: 200px; transition: margin-left 0.3s, background 0.3s, color 0.3s;}
body.no-sidebar { margin-left: 0; }
.nav{background:var(--nav-bg);color:white;padding:14px 22px;
     display:flex;justify-content:space-between;align-items:center;
     box-shadow:0 2px 8px rgba(0,0,0,.08);position:sticky;top:0;z-index:50; margin-left: -200px; transition: margin-left 0.3s, background 0.3s;}
body.no-sidebar .nav { margin-left: 0; }
.nav .brand{font-weight:800;font-size:22px;letter-spacing:1px;display:flex;align-items:center;gap:10px}
.nav a{color:white;text-decoration:none;margin-left:16px;font-weight:500;opacity:.95}
.nav a:hover{opacity:1;text-decoration:underline}
.container{max-width:1100px;margin:0 auto;padding:24px 18px 60px}
.card{background:var(--card-bg);border-radius:16px;padding:22px;
      box-shadow:0 6px 22px rgba(74,165,208,.12);margin-bottom:18px; transition: background 0.3s;}
h1,h2,h3{color:var(--ink);margin-bottom:12px}
h1{font-size:26px}
h2{font-size:20px}
.btn{display:inline-block;padding:11px 20px;border-radius:10px;
     background:var(--sky-dark);color:white;text-decoration:none;
     border:none;cursor:pointer;font-weight:600;font-size:14px}
.btn:hover{background:#2F8CBB}
.btn.ghost{background:transparent;color:var(--sky-dark);border:2px solid var(--sky-dark)}
.btn.danger{background:var(--danger)}
.btn.ok{background:var(--ok)}
input,select,textarea{width:100%;padding:11px 13px;border:2px solid var(--sky-light);
     border-radius:10px;font-size:15px;margin:6px 0 14px;outline:none;
     transition:.2s;background:var(--input-bg);color:var(--ink)}
input:focus,select:focus,textarea:focus{border-color:var(--sky-dark)}
label{font-weight:600;font-size:14px;color:var(--muted)}
.flash{padding:12px 16px;border-radius:10px;margin-bottom:14px;font-weight:500}
.flash.success{background:#D4F5E3;color:#1E7A45}
.flash.danger{background:#FBE1DE;color:#A02A1B}
.flash.warning{background:#FFF1D6;color:#8A5C00}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.lesson{background:var(--card-bg);border-radius:14px;padding:16px;
        box-shadow:0 4px 14px rgba(74,165,208,.10);
        border-left:5px solid var(--sky);transition:.2s;position:relative}
.lesson:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(74,165,208,.20)}
.lesson .cat{font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.6px}
.lesson .de{font-size:17px;font-weight:700;margin:6px 0}
.lesson .fr{font-size:14px;color:var(--muted)}
.lesson .actions{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
.badge{display:inline-block;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:700}
.badge.done{background:#D4F5E3;color:#1E7A45}
.badge.todo{background:#FFF1D6;color:#8A5C00}
.player{background:linear-gradient(135deg,var(--sky-dark),#2F8CBB);
        color:white;border-radius:18px;padding:22px;margin-bottom:18px}
.player .fr{font-size:15px;opacity:.9;margin-bottom:6px}
.player .de{font-size:26px;font-weight:800;margin-bottom:16px}
.player .ctrl{display:flex;gap:10px;flex-wrap:wrap}
.player .ctrl button{background:rgba(255,255,255,.22);color:white;border:none;
        padding:11px 18px;border-radius:10px;font-weight:600;cursor:pointer;font-size:14px}
.player .ctrl button:hover{background:rgba(255,255,255,.35)}
.player .ctrl button.primary{background:white;color:var(--sky-dark)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--border-light)}
th{background:var(--sky-light);font-weight:700;color:var(--ink)}
.hero{background:linear-gradient(135deg,var(--sky),#B8E2F5);color:white;
      border-radius:22px;padding:40px 30px;text-align:center;margin-bottom:22px}
.hero h1{color:white;font-size:32px}
.hero p{opacity:.95;margin:10px 0 22px;font-size:16px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px}
.stat{background:var(--card-bg);border-radius:14px;padding:18px;text-align:center;
      box-shadow:0 4px 14px rgba(74,165,208,.10)}
.stat .num{font-size:28px;font-weight:800;color:var(--sky-dark)}
.stat .lbl{font-size:13px;color:var(--muted);margin-top:4px}
.quiz-opt{display:block;background:var(--card-bg);border:2px solid var(--sky-light);
      border-radius:10px;padding:13px 16px;margin:8px 0;cursor:pointer;transition:.15s}
.quiz-opt:hover{border-color:var(--sky-dark)}
.quiz-opt input{margin-right:10px;width:auto}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.tabs a{padding:8px 16px;border-radius:20px;background:var(--card-bg);text-decoration:none;
      font-size:13px;font-weight:600;color:var(--muted);border:2px solid var(--sky-light)}
.tabs a.active{background:var(--sky-dark);color:white;border-color:var(--sky-dark)}
footer{text-align:center;padding:24px;color:var(--muted);font-size:13px}
footer a { color: var(--muted); text-decoration: underline; margin: 0 10px;}

.sidebar {
  position: fixed; top: 0; left: 0; bottom: 0; width: 200px;
  background: var(--sidebar-bg); color: white; padding: 20px 15px; z-index: 60;
  display: flex; flex-direction: column; gap: 20px;
}
.sidebar h3 { color: #87CEEB; font-size: 14px; text-transform: uppercase; margin-bottom: 10px; letter-spacing: 1px;}
.sidebar .level { padding: 10px; border-radius: 8px; background: rgba(255,255,255,0.05); margin-bottom: 8px; cursor: not-allowed; opacity: 0.6;}
.sidebar .level .tag { font-size: 10px; background: #E74C3C; padding: 2px 6px; border-radius: 4px; float: right; font-weight: bold;}
.sidebar .level.active { background: #4AA5D0; opacity: 1; cursor: pointer;}
.sidebar .level.active .tag { display: none;}

.mobile-menu-btn {
  display: none;
  background: rgba(255,255,255,0.2);
  color: white;
  border: none;
  font-size: 22px;
  width: 42px; height: 42px;
  border-radius: 10px;
  cursor: pointer;
  margin-left: 8px;
}
.mobile-menu-btn:hover { background: rgba(255,255,255,0.35); }

.mobile-drawer {
  position: fixed; top: 0; right: -280px; bottom: 0; width: 280px;
  background: var(--sidebar-bg); color: white;
  z-index: 200; padding: 20px; transition: right 0.3s ease;
  box-shadow: -4px 0 20px rgba(0,0,0,0.3);
}
.mobile-drawer.open { right: 0; }
.mobile-drawer h3 { color: #87CEEB; font-size: 13px; text-transform: uppercase; margin-bottom: 12px; }
.mobile-drawer .close-x {
  position: absolute; top: 12px; right: 14px; background: none; border: none;
  color: white; font-size: 24px; cursor: pointer;
}
.mobile-drawer .level { padding: 12px; border-radius: 8px; background: rgba(255,255,255,0.06); margin-bottom: 10px; opacity: 0.7;}
.mobile-drawer .level.active { background: #4AA5D0; opacity: 1;}
.mobile-drawer .level .tag { font-size: 10px; background: #E74C3C; padding: 2px 6px; border-radius: 4px; float: right; font-weight: bold;}
.mobile-drawer .level.active .tag { display: none;}

.theme-toggle {
  background: rgba(255,255,255,0.2);
  color: white;
  border: none;
  padding: 8px 12px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 14px;
  margin-left: 8px;
}
.theme-toggle:hover { background: rgba(255,255,255,0.35); }

@media (max-width: 800px) {
  body { margin-left: 0; }
  .nav { margin-left: 0; padding: 10px 15px; flex-direction: row; align-items: center; gap: 8px; flex-wrap: wrap;}
  .nav .brand { font-size: 16px; }
  .nav > div:nth-child(2) { display: flex; flex-wrap: wrap; gap: 8px; margin-left: 0; width: 100%;}
  .nav a { margin-left: 0; font-size: 12px; }
  .sidebar { display: none; }
  .mobile-menu-btn { display: inline-block; }
}

#cookie-banner {
  position: fixed; bottom: 0; left: 0; right: 0;
  background: #1a2a35; color: white; padding: 15px 20px;
  display: flex; justify-content: space-between; align-items: center;
  z-index: 999; font-size: 14px; box-shadow: 0 -4px 10px rgba(0,0,0,0.2);
  transform: translateY(100%); transition: transform 0.3s;
}
#cookie-banner.show { transform: translateY(0); }
#cookie-banner button {
  background: #87CEEB; color: #0F2A3F; border: none; padding: 8px 16px;
  border-radius: 8px; font-weight: bold; cursor: pointer; margin-left: 10px;
}

#global-player {
  position: fixed; bottom: 0; left: 0; right: 0;
  background: #1a2a35; color: white; padding: 12px 20px;
  display: none; justify-content: space-between; align-items: center; gap: 12px;
  box-shadow: 0 -4px 15px rgba(0,0,0,0.2); z-index: 100;
}
#global-player .info { font-weight: 600; font-size: 15px; min-width: 0; }
#global-player .info small { display: block; color: #87CEEB; font-size: 13px; font-weight: normal;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#global-player .gp-ctrl { display: flex; gap: 8px; flex-shrink: 0; }
#global-player .gp-btn { background: rgba(255,255,255,.18); color: white; border: none;
  padding: 8px 14px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 14px; }
#global-player .gp-btn:hover { background: rgba(255,255,255,.3); }
#global-player .gp-stop { background: var(--danger); }
#global-player .gp-stop:hover { background: #c0392b; }

#voice-toast {
  position: fixed; left: 50%; bottom: 90px; transform: translateX(-50%) translateY(20px);
  background: #A02A1B; color: white; padding: 12px 18px; border-radius: 10px;
  font-size: 14px; font-weight: 500; max-width: 90%; text-align: center;
  opacity: 0; pointer-events: none; transition: .25s; z-index: 200;
}
#voice-toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

.pwd-wrapper { position: relative; }
.pwd-wrapper input { padding-right: 40px; }
.pwd-toggle { position: absolute; right: 12px; top: 14px; cursor: pointer; font-size: 18px; color: var(--muted); }
.pwd-toggle:hover { color: var(--ink); }

.fiche { background: var(--card-bg); border-radius: 14px; padding: 18px; margin-bottom: 14px; border-left: 5px solid var(--sky); }
.fiche h3 { color: var(--sky-dark); font-size: 16px; margin-bottom: 10px; }
.fiche .content { font-family: 'Courier New', monospace; background: var(--input-bg); padding: 12px; border-radius: 8px; font-size: 13px; white-space: pre-wrap; line-height: 1.6; color: var(--ink); }
.fiche .explanation { margin-top: 10px; font-size: 13px; color: var(--muted); font-style: italic; padding: 10px; background: rgba(135,206,235,0.12); border-radius: 8px; }

.nomakk-section { background: var(--card-bg); border-radius: 14px; padding: 18px; margin-bottom: 14px; border-left: 5px solid var(--warn); }
.nomakk-section h3 { color: var(--warn); font-size: 16px; margin-bottom: 10px; }
.nomakk-section .content { background: var(--input-bg); padding: 14px; border-radius: 8px; font-size: 13px; white-space: pre-wrap; line-height: 1.7; color: var(--ink); font-family: 'Segoe UI', sans-serif; }
.nomakk-section .explanation { margin-top: 10px; font-size: 13px; color: var(--ink); font-style: italic; padding: 10px; background: rgba(243,156,18,0.12); border-radius: 8px; border-left: 3px solid var(--warn); }

/* === NEFERTI : chat vocal === */
.neferti-header {
  background: linear-gradient(135deg, #FF9BC7, #FF6FA5);
  color: white; border-radius: 18px; padding: 22px; margin-bottom: 18px;
  display: flex; align-items: center; gap: 16px;
}
.neferti-avatar {
  width: 70px; height: 70px; border-radius: 50%;
  background: white; display: flex; align-items: center; justify-content: center;
  font-size: 36px; flex-shrink: 0;
  box-shadow: 0 0 0 4px rgba(255,255,255,0.3);
}
.neferti-avatar.listening { animation: pulse 1s infinite; }
@keyframes pulse {
  0%,100% { box-shadow: 0 0 0 4px rgba(255,255,255,0.3); }
  50%     { box-shadow: 0 0 0 12px rgba(255,255,255,0.15); }
}
.neferti-header h2 { color: white; margin: 0; }
.neferti-header p  { opacity: 0.95; margin: 4px 0 0; font-size: 14px; }
#neferti-chat {
  background: var(--card-bg); border-radius: 16px; padding: 18px;
  min-height: 320px; max-height: 60vh; overflow-y: auto;
  margin-bottom: 16px; box-shadow: 0 4px 14px rgba(255,111,165,.15);
  display: flex; flex-direction: column; gap: 12px;
}
.msg {
  padding: 12px 16px; border-radius: 14px; max-width: 85%;
  font-size: 14px; line-height: 1.5; animation: fadeIn 0.25s ease;
}
@keyframes fadeIn { from { opacity: 0; transform: translateY(6px);} to {opacity:1; transform:none;} }
.msg.neferti { background: #FFE4EE; color: #5A1B33; align-self: flex-start; border-bottom-left-radius: 4px; }
.msg.user    { background: #D4F5E3; color: #1E7A45; align-self: flex-end;   border-bottom-right-radius: 4px; }
html[data-theme="dark"] .msg.neferti { background: #4a2030; color: #FFD6E4; }
html[data-theme="dark"] .msg.user    { background: #1e4a35; color: #D4F5E3; }
.msg .de { font-weight: 700; margin-bottom: 4px; }
.msg .fr { opacity: 0.85; font-size: 13px; }
.msg .meta { font-size: 11px; color: var(--muted); margin-top: 6px; }
.msg .score-ok   { color: #1E7A45; font-weight: 700; }
.msg .score-mid  { color: #8A5C00; font-weight: 700; }
.msg .score-bad  { color: #A02A1B; font-weight: 700; }
.neferti-controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; justify-content: center; }
.mic-btn {
  background: linear-gradient(135deg, #FF6FA5, #FF9BC7);
  color: white; border: none; border-radius: 50%;
  width: 74px; height: 74px; font-size: 30px; cursor: pointer;
  box-shadow: 0 4px 14px rgba(255,111,165,.4); transition: .2s;
}
.mic-btn:hover { transform: scale(1.05); }
.mic-btn.listening {
  background: linear-gradient(135deg, #E74C3C, #FF6B5B);
  animation: micPulse 1s infinite;
}
@keyframes micPulse {
  0%,100% { box-shadow: 0 0 0 0 rgba(231,76,60,0.5); }
  50%     { box-shadow: 0 0 0 18px rgba(231,76,60,0); }
}
.neferti-status {
  text-align: center; font-size: 13px; color: var(--muted); margin: 8px 0;
  min-height: 20px;
}
.neferti-inputs { display: flex; gap: 10px; margin-top: 12px; }
.neferti-inputs input { flex: 1; margin: 0; }

/* === v4.1 : menu déroulant, tiroir mobile, Sprechen, compte === */
.nav-links { display: inline-flex; align-items: center; flex-wrap: wrap; }
.nav-dd { position: relative; display: inline-block; margin-left: 16px; }
.nav-dd summary { cursor: pointer; list-style: none; font-weight: 500; opacity: .95; color: white; }
.nav-dd summary::-webkit-details-marker { display: none; }
.nav-dd summary:hover { opacity: 1; text-decoration: underline; }
.nav-dd-menu {
  position: absolute; top: 140%; left: 0; z-index: 90; min-width: 170px;
  background: var(--nav-bg); border-radius: 10px; padding: 8px 6px;
  box-shadow: 0 8px 24px rgba(0,0,0,.25); display: flex; flex-direction: column;
}
.nav-dd-menu a { margin: 0; padding: 8px 12px; border-radius: 8px; white-space: nowrap; }
.nav-dd-menu a:hover { background: rgba(255,255,255,.15); text-decoration: none; }
.mobile-drawer { overflow-y: auto; }
.drawer-links a {
  display: block; color: white; text-decoration: none; padding: 11px 6px;
  border-bottom: 1px solid rgba(255,255,255,.12); font-size: 15px;
}
.drawer-links a:hover { background: rgba(255,255,255,.08); }
@media (max-width: 800px) {
  .nav-links.member { display: none; }
}
.sp-box { background: var(--sky-light); padding: 16px; border-radius: 10px; margin: 14px 0; }
.sp-actions { display: flex; flex-direction: column; align-items: center; gap: 6px; margin: 14px 0; }
.res-score { font-size: 28px; font-weight: 800; }
.res-ok { color: #1E7A45; }
.res-mid { color: #8A5C00; }
.res-bad { color: #A02A1B; }
.danger-zone { border-left: 5px solid var(--danger); }
/* === v4.2 : cours des 4 cas, Neferti intelligente === */
.nomakk-section .nk-content { white-space: normal; }
.nk-pair { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px dashed var(--border-light); gap: 8px; }
.nk-txt { flex: 1; font-size: 13px; line-height: 1.5; }
.nk-fr { color: var(--muted); font-weight: normal; }
.nk-line { font-size: 13px; line-height: 1.7; padding: 1px 0; color: var(--ink); }
.nk-gap { height: 8px; }
.nk-chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0; }
.nk-chip { background: var(--input-bg); color: var(--ink); text-decoration: none; padding: 7px 14px; border-radius: 999px; font-size: 13px; font-weight: 600; border: 1px solid var(--border-light); }
.nk-chip:hover { background: var(--warn); color: #fff; }
.nk-group { margin-top: 18px; scroll-margin-top: 80px; }
.neferti-tools { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }
.neferti-tool { flex: 1; min-width: 200px; }
.neferti-tool label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
.neferti-tool select { width: 100%; margin: 0; }
.neferti-actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
/* === v4.3 : guide === */
.gd-row { padding: 8px 0; border-bottom: 1px dashed var(--border-light); display: flex; gap: 8px; align-items: center; justify-content: space-between; }
.gd-main { flex: 1; font-size: 13px; line-height: 1.55; }
.gd-ex { display: block; }
.gd-btns { display: flex; gap: 6px; flex-shrink: 0; }
.gd-pp { color: var(--warn); font-weight: 700; }
.gd-alpha { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 8px; }
.gd-letter { background: var(--input-bg); border: 1px solid var(--border-light); border-radius: 12px; padding: 10px; text-align: center; font-size: 13px; }
.gd-letter .big { font-size: 26px; font-weight: 800; display: block; }
.neferti-example { flex-basis: 100%; background: var(--sky-light); border-radius: 10px; padding: 12px; font-size: 14px; line-height: 1.6; }
</style>
"""

AUDIO_JS = r"""
(function () {
  'use strict';

  var synth = window.speechSynthesis;
  var supported = !!(synth && window.SpeechSynthesisUtterance);
  var voices = [];
  var pending = new Set();
  var token = 0;
  var warned = {};
  var list = [];
  var idx = 0;
  var listTitle = '';
  var paused = false;
  var ttsFails = 0;
  var curMode = 'tts';
  var au = null;
  var auResolve = null;
  var silCache = {};
  var mediaReady = false;

  var RATE_FR = 0.9;
  var RATE_DE = 0.75;
  var MP3_RATE_DE = 0.85;
  var GAP_FR_DE = 1200;
  var GAP_NEXT = 2500;

  var LS_ITEMS = 'natho_pl_items';
  var LS_IDX = 'natho_pl_idx';
  var LS_TITLE = 'natho_pl_title';
  var LS_TIME = 'natho_pl_time';

  var ALL_TITLES = {
    vocab: 'Tout le vocabulaire',
    lessons: 'Toutes les phrases',
    mix: 'Phrases + vocabulaire',
    dialogues: 'Tous les dialogues'
  };

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function toast(msg) {
    var t = document.getElementById('voice-toast');
    if (!t) { alert(msg); return; }
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.classList.remove('show'); }, 6000);
  }

  function saveItems() {
    try {
      localStorage.setItem(LS_ITEMS, JSON.stringify(list));
      localStorage.setItem(LS_TITLE, listTitle);
      localStorage.setItem(LS_IDX, String(idx));
      localStorage.setItem(LS_TIME, String(Date.now()));
    } catch (e) {}
  }

  function saveIdx() {
    try {
      localStorage.setItem(LS_IDX, String(idx));
      localStorage.setItem(LS_TIME, String(Date.now()));
    } catch (e) {}
  }

  function clearState() {
    try {
      [LS_ITEMS, LS_IDX, LS_TITLE, LS_TIME].forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) {}
  }

  function normLang(l) { return (l || '').replace('_', '-').toLowerCase(); }

  function refreshVoices() {
    if (!supported) return;
    var v = synth.getVoices();
    if (v && v.length) voices = v;
  }

  if (supported) {
    refreshVoices();
    if (synth.addEventListener) synth.addEventListener('voiceschanged', refreshVoices);
    else synth.onvoiceschanged = refreshVoices;
    var tries = 0;
    var poll = setInterval(function () {
      refreshVoices();
      tries++;
      if (voices.length || tries > 24) clearInterval(poll);
    }, 250);
  }

  function pickVoice(lang) {
    var prefix = normLang(lang).slice(0, 2);
    var all = voices.filter(function (v) { return normLang(v.lang).indexOf(prefix) === 0; });
    if (!all.length) return null;
    var exact = all.filter(function (v) { return normLang(v.lang) === normLang(lang); });
    var pool = exact.length ? exact : all;
    return pool.find(function (v) { return /google/i.test(v.name); }) ||
           pool.find(function (v) { return /natural|neural|online/i.test(v.name); }) ||
           pool[0];
  }

  function warnNoVoice(lang) {
    var key = lang.slice(0, 2);
    if (warned[key] || !voices.length) return;
    warned[key] = true;
    var nom = key === 'de' ? "allemande" : "française";
    toast("Aucune voix " + nom + " trouvée sur cet appareil.");
  }

  function ensure() {
    if (!supported) {
      toast("La synthèse vocale n'est pas supportée par ce navigateur.");
      return false;
    }
    return true;
  }

  function say(text, lang, rate) {
    return new Promise(function (resolve) {
      if (!text) { resolve(); return; }
      var u = new SpeechSynthesisUtterance(text);
      var v = pickVoice(lang);
      if (v) { u.voice = v; u.lang = v.lang.replace('_', '-'); }
      else { u.lang = lang; warnNoVoice(lang); }
      u.rate = rate;
      u.pitch = 1;
      u.volume = 1;

      var done = false;
      var timer = null;
      function finish() {
        if (done) return;
        done = true;
        clearTimeout(timer);
        pending.delete(u);
        resolve();
      }
      u.onend = finish;
      u.onerror = finish;
      timer = setTimeout(finish, 3000 + (text.length * 140) / rate);

      pending.add(u);
      try { synth.speak(u); } catch (e) { finish(); }
    });
  }

  function useMp3() { return window.NATHO_TTS === true && ttsFails < 2; }

  function getAudio() {
    if (!au) au = document.getElementById('natho-audio');
    if (!au) {
      au = document.createElement('audio');
      au.setAttribute('playsinline', '');
      document.body.appendChild(au);
    }
    return au;
  }

  function silenceUrl(ms) {
    if (silCache[ms]) return silCache[ms];
    var rate = 8000;
    var n = Math.floor(rate * ms / 1000);
    var buf = new ArrayBuffer(44 + n);
    var v = new DataView(buf);
    function ws(o, s) { for (var i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); }
    ws(0, 'RIFF'); v.setUint32(4, 36 + n, true); ws(8, 'WAVE'); ws(12, 'fmt ');
    v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
    v.setUint32(24, rate, true); v.setUint32(28, rate, true);
    v.setUint16(32, 1, true); v.setUint16(34, 8, true);
    ws(36, 'data'); v.setUint32(40, n, true);
    var u8 = new Uint8Array(buf);
    for (var i = 44; i < 44 + n; i++) u8[i] = 128;
    silCache[ms] = URL.createObjectURL(new Blob([buf], { type: 'audio/wav' }));
    return silCache[ms];
  }

  function playUrl(url, rate) {
    return new Promise(function (resolve) {
      var a = getAudio();
      var finished = false;
      var started = false;
      var wd = null;
      function cleanup() {
        clearTimeout(wd);
        a.removeEventListener('ended', onEnd);
        a.removeEventListener('error', onErr);
        a.removeEventListener('playing', onPlaying);
      }
      function done(ok) {
        if (finished) return;
        finished = true;
        cleanup();
        auResolve = null;
        resolve(ok);
      }
      function onEnd() { done(true); }
      function onErr() { done(false); }
      function onPlaying() { started = true; clearTimeout(wd); }

      auResolve = done;
      a.addEventListener('ended', onEnd);
      a.addEventListener('error', onErr);
      a.addEventListener('playing', onPlaying);
      wd = setTimeout(function () {
        if (!started) { try { a.pause(); } catch (e) {} done(false); }
      }, 20000);
      try {
        a.src = url;
        a.defaultPlaybackRate = rate;
        a.playbackRate = rate;
        var p = a.play();
        if (p && p.catch) p.catch(function () { done(false); });
      } catch (e) { done(false); }
    });
  }

  function auStop() {
    if (au) { try { au.pause(); } catch (e) {} }
    if (auResolve) { var r = auResolve; auResolve = null; r(false); }
    if ('mediaSession' in navigator) {
      try { navigator.mediaSession.playbackState = 'none'; } catch (e) {}
    }
  }

  async function seg(text, lang, my) {
    if (!text) return;
    if (useMp3()) {
      curMode = 'mp3';
      var url = '/tts?lang=' + lang + '&text=' + encodeURIComponent(text);
      var ok = await playUrl(url, lang === 'de' ? MP3_RATE_DE : 1);
      if (my !== token) return;
      if (ok) { ttsFails = 0; return; }
      ttsFails++;
    }
    if (my !== token) return;
    if (!supported) return;
    curMode = 'tts';
    await say(text, lang === 'de' ? 'de-DE' : 'fr-FR', lang === 'de' ? RATE_DE : RATE_FR);
  }

  async function gap(ms, my) {
    if (useMp3()) {
      curMode = 'mp3';
      var ok = await playUrl(silenceUrl(ms), 1);
      if (my !== token) return;
      if (ok) return;
    }
    if (my !== token) return;
    await sleep(ms);
  }

  function prefetch(from) {
    if (!useMp3()) return;
    for (var k = from; k < from + 2 && k < list.length; k++) {
      var it = list[k];
      try {
        fetch('/tts?lang=fr&text=' + encodeURIComponent(it.fr), { credentials: 'same-origin' }).catch(function () {});
        fetch('/tts?lang=de&text=' + encodeURIComponent(it.de), { credentials: 'same-origin' }).catch(function () {});
      } catch (e) {}
    }
  }

  function el(id) { return document.getElementById(id); }

  function hidePlayer() {
    var p = el('global-player');
    if (p) p.style.display = 'none';
  }

  function showPlayer(item) {
    var p = el('global-player');
    if (p) p.style.display = 'flex';
    var c = el('gp-count');
    if (c) c.textContent = (listTitle ? listTitle + ' · ' : '') + 'Lecture ' + (idx + 1) + ' / ' + list.length;
    var t = el('gp-text');
    if (t) t.textContent = item.de + '  —  ' + item.fr;
    var r = el('gp-resume');
    if (r) r.style.display = 'none';
    var b = el('gp-pause');
    if (b) { b.style.display = ''; b.textContent = paused ? '▶' : '⏸'; }
  }

  function showResumeBar(title, i, n) {
    var p = el('global-player');
    if (!p) return;
    p.style.display = 'flex';
    var c = el('gp-count');
    if (c) c.textContent = 'Playlist interrompue';
    var t = el('gp-text');
    if (t) t.textContent = (title ? title + ' — ' : '') + 'reprise à ' + (i + 1) + ' / ' + n;
    var r = el('gp-resume');
    if (r) r.style.display = '';
    var b = el('gp-pause');
    if (b) b.style.display = 'none';
  }

  function initMedia() {
    if (mediaReady || !('mediaSession' in navigator)) return;
    mediaReady = true;
    var ms = navigator.mediaSession;
    function setH(name, fn) { try { ms.setActionHandler(name, fn); } catch (e) {} }
    setH('play', function () { if (paused) togglePause(); });
    setH('pause', function () { if (!paused) togglePause(); });
    setH('previoustrack', function () { jump(-1); });
    setH('nexttrack', function () { jump(1); });
    setH('stop', function () { stopPlaylist(); });
  }

  function setMedia(item) {
    if (!('mediaSession' in navigator)) return;
    initMedia();
    try {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: item.de,
        artist: item.fr,
        album: 'NATHO · Deutsch A1'
      });
      navigator.mediaSession.playbackState = paused ? 'paused' : 'playing';
    } catch (e) {}
  }

  function togglePause() {
    if (!list.length) return;
    if (!paused) {
      if (curMode === 'mp3' && au) { try { au.pause(); } catch (e) {} }
      else if (supported) { try { synth.pause(); } catch (e) {} }
      paused = true;
    } else {
      if (curMode === 'mp3' && au) {
        var p = au.play();
        if (p && p.catch) p.catch(function () {});
      } else if (supported) { try { synth.resume(); } catch (e) {} }
      paused = false;
    }
    try { navigator.mediaSession.playbackState = paused ? 'paused' : 'playing'; } catch (e) {}
    var b = el('gp-pause');
    if (b) b.textContent = paused ? '▶' : '⏸';
  }

  async function begin() {
    var busy = supported && (synth.speaking || synth.pending);
    token++;
    list = [];
    idx = 0;
    listTitle = '';
    paused = false;
    hidePlayer();
    clearState();
    auStop();
    if (supported) {
      if (synth.paused) synth.resume();
      synth.cancel();
    }
    pending.clear();
    if (busy) await sleep(120);
    return token;
  }

  async function speak(text, lang) {
    if (!ensure()) return;
    lang = lang || 'de-DE';
    var my = await begin();
    if (my !== token) return;
    curMode = 'tts';
    await say(text, lang, lang.indexOf('de') === 0 ? RATE_DE : RATE_FR);
  }

  async function speakPair(fr, de) {
    if (!ensure()) return;
    var my = await begin();
    if (my !== token) return;
    curMode = 'tts';
    await say(fr, 'fr-FR', RATE_FR);
    if (my !== token) return;
    await sleep(GAP_FR_DE);
    if (my !== token) return;
    await say(de, 'de-DE', RATE_DE);
  }

  async function loop(my) {
    while (my === token && idx < list.length) {
      var it = list[idx];
      saveIdx();
      showPlayer(it);
      setMedia(it);
      prefetch(idx + 1);
      await seg(it.fr, 'fr', my);
      if (my !== token) return;
      await gap(GAP_FR_DE, my);
      if (my !== token) return;
      await seg(it.de, 'de', my);
      if (my !== token) return;
      await gap(GAP_NEXT, my);
      if (my !== token) return;
      idx++;
    }
    if (my === token) stopPlaylist();
  }

  async function startPlaylist(items, title) {
    if (!useMp3() && !ensure()) return;
    if (!items || !items.length) { toast("La playlist est vide."); return; }
    ttsFails = 0;
    var my = await begin();
    if (my !== token) return;
    list = items;
    idx = 0;
    listTitle = title || '';
    saveItems();
    loop(my);
  }

  function flat(kind) {
    var d = window.NATHO_PLAYLISTS || {};
    var src = d[kind] || {};
    var cats = (d.order && d.order[kind]) || Object.keys(src);
    var r = [];
    cats.forEach(function (c) { if (src[c]) r = r.concat(src[c]); });
    return r;
  }

  function getItems(kind, key) {
    var d = window.NATHO_PLAYLISTS || {};
    if (kind === 'all') {
      if (key === 'vocab') return flat('vocab');
      if (key === 'lessons') return flat('lessons');
      if (key === 'mix') return flat('lessons').concat(flat('vocab'));
      if (key === 'dialogues') return flat('dialogues');
      return null;
    }
    return d[kind] && d[kind][key];
  }

  function startPlaylistByKey(kind, key) {
    var title = kind === 'all' ? (ALL_TITLES[key] || key) : key;
    startPlaylist(getItems(kind, key), title);
  }

  async function resumePlaylist() {
    var items = [];
    var i = 0;
    var title = '';
    try {
      items = JSON.parse(localStorage.getItem(LS_ITEMS) || '[]');
      i = parseInt(localStorage.getItem(LS_IDX) || '0', 10) || 0;
      title = localStorage.getItem(LS_TITLE) || '';
    } catch (e) { return; }
    if (!items.length) return;
    if (!useMp3() && !ensure()) return;
    ttsFails = 0;
    var my = await begin();
    if (my !== token) return;
    list = items;
    idx = Math.min(i, items.length - 1);
    listTitle = title;
    saveItems();
    loop(my);
  }

  function stopPlaylist() {
    token++;
    list = [];
    idx = 0;
    listTitle = '';
    paused = false;
    auStop();
    if (supported) {
      if (synth.paused) synth.resume();
      synth.cancel();
    }
    pending.clear();
    hidePlayer();
    clearState();
  }

  async function jump(delta) {
    if (!list.length) return;
    var n = idx + delta;
    if (n < 0) n = 0;
    if (n >= list.length) { stopPlaylist(); return; }
    var busy = supported && (synth.speaking || synth.pending);
    token++;
    var my = token;
    idx = n;
    paused = false;
    auStop();
    if (supported) {
      if (synth.paused) synth.resume();
      synth.cancel();
    }
    pending.clear();
    if (busy) await sleep(120);
    if (my !== token) return;
    loop(my);
  }

  function initResume() {
    try {
      var raw = localStorage.getItem(LS_ITEMS);
      if (!raw) return;
      var t = parseInt(localStorage.getItem(LS_TIME) || '0', 10);
      if (!t || Date.now() - t > 86400000) { clearState(); return; }
      var items = JSON.parse(raw);
      var i = parseInt(localStorage.getItem(LS_IDX) || '0', 10) || 0;
      if (!items.length || i >= items.length) { clearState(); return; }
      showResumeBar(localStorage.getItem(LS_TITLE) || '', i, items.length);
    } catch (e) {}
  }

  function runScripts(root) {
    root.querySelectorAll('script').forEach(function (old) {
      var s = document.createElement('script');
      if (old.src) s.src = old.src; else s.text = old.textContent;
      old.parentNode.replaceChild(s, old);
    });
  }

  async function go(url, opts, push) {
    try {
      var res = await fetch(url, opts || { credentials: 'same-origin', cache: 'no-cache' });
      var ct = res.headers.get('content-type') || '';
      if (ct.indexOf('text/html') < 0) { window.location.href = url; return; }
      var html = await res.text();
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var newC = doc.querySelector('.container');
      var oldC = document.querySelector('.container');
      if (!newC || !oldC) { window.location.href = res.url || url; return; }
      var newN = doc.querySelector('.nav');
      var oldN = document.querySelector('.nav');
      if (newN && oldN) oldN.innerHTML = newN.innerHTML;
      var newS = doc.getElementById('side-wrap');
      var oldS = document.getElementById('side-wrap');
      if (newS && oldS) oldS.innerHTML = newS.innerHTML;
      if (doc.body) document.body.className = doc.body.className;
      oldC.innerHTML = newC.innerHTML;
      if (window.syncThemeButtons) window.syncThemeButtons();
      if (window.closeMobileMenu) window.closeMobileMenu();
      document.title = doc.title;
      if (push) history.pushState({}, '', res.url || url);
      runScripts(oldC);
      window.scrollTo(0, 0);
    } catch (err) {
      window.location.href = url;
    }
  }

  function shouldNav(a, e) {
    if (!a || !a.href) return false;
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return false;
    if (a.target && a.target !== '_self') return false;
    if (a.hasAttribute('download')) return false;
    if (a.origin !== window.location.origin) return false;
    if (a.pathname === window.location.pathname && a.search === window.location.search && a.hash) return false;
    return true;
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    var b = t && t.closest ? t.closest('[data-say]') : null;
    if (b) {
      e.preventDefault();
      var mode = b.getAttribute('data-say');
      var fr = b.getAttribute('data-fr') || '';
      var de = b.getAttribute('data-de') || '';
      if (mode === 'pair') speakPair(fr, de);
      else if (mode === 'de') speak(de, 'de-DE');
      else if (mode === 'fr') speak(fr, 'fr-FR');
      else if (mode === 'playlist') startPlaylistByKey(b.getAttribute('data-kind'), b.getAttribute('data-key'));
      return;
    }
    var a = t && t.closest ? t.closest('a[href]') : null;
    if (a && shouldNav(a, e)) {
      e.preventDefault();
      if (a.pathname === '/logout') stopPlaylist();
      go(a.href, { credentials: 'same-origin', cache: 'no-cache' }, true);
    }
  });

  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f || f.tagName !== 'FORM' || e.defaultPrevented) return;
    var method = (f.getAttribute('method') || 'get').toLowerCase();
    if (method !== 'post') return;
    e.preventDefault();
    go(f.action || window.location.href, { method: 'POST', body: new FormData(f), credentials: 'same-origin' }, true);
  });

  window.addEventListener('popstate', function () {
    go(window.location.href, { credentials: 'same-origin', cache: 'no-cache' }, false);
  });

  initResume();

  window.NathoAudio = {
    speak: speak,
    speakPair: speakPair,
    startPlaylist: startPlaylist,
    startPlaylistByKey: startPlaylistByKey,
    stopPlaylist: stopPlaylist,
    resume: resumePlaylist,
    togglePause: togglePause,
    prev: function () { jump(-1); },
    next: function () { jump(1); }
  };
  window.speak = speak;
  window.speakPair = speakPair;
  window.startPlaylist = startPlaylist;
  window.stopPlaylist = stopPlaylist;
})();
"""

# === NEFERTI : voix féminine DE (pitch 1.15) + reconnaissance vocale ===
NEFERTI_JS = r"""
(function(){
  'use strict';

  var synth = window.speechSynthesis;
  var voices = [];
  var selectedVoice = null;
  var NEFERTI_PITCH = 1.15;
  var NEFERTI_RATE = 0.85;

  function refreshVoices() {
    if (!synth) return;
    voices = synth.getVoices() || [];
    var de = voices.filter(function(v){ return (v.lang||'').toLowerCase().indexOf('de') === 0; });
    var females = de.filter(function(v){ return /female|frau|anna|maja|zira|helena|katja/i.test(v.name); });
    var pick = females[0] ||
               de.find(function(v){ return /google/i.test(v.name); }) ||
               de.find(function(v){ return /natural|neural/i.test(v.name); }) ||
               de[0] || null;
    selectedVoice = pick;
  }
  if (synth) {
    refreshVoices();
    if (synth.addEventListener) synth.addEventListener('voiceschanged', refreshVoices);
    else synth.onvoiceschanged = refreshVoices;
  }

  window.NefertiSay = function(text) {
    if (!synth || !text) return;
    try { if (window.NathoAudio && window.NathoAudio.stopPlaylist) window.NathoAudio.stopPlaylist(); } catch(e){}
    try { synth.cancel(); } catch(e){}
    var u = new SpeechSynthesisUtterance(text);
    if (selectedVoice) { u.voice = selectedVoice; u.lang = selectedVoice.lang; }
    else u.lang = 'de-DE';
    u.pitch = NEFERTI_PITCH;
    u.rate = NEFERTI_RATE;
    u.volume = 1;
    synth.speak(u);
  };

  // Reconnaissance vocale (allemand)
  var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  var recognition = null;
  var isListening = false;

  window.NefertiSupported = !!SR;

  window.NefertiStartListening = function(onResult, onEnd) {
    if (!SR) { alert("La reconnaissance vocale n'est pas supportée sur ce navigateur. Utilise Chrome ou Edge."); return; }
    if (isListening) return;
    recognition = new SR();
    recognition.lang = 'de-DE';
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.maxAlternatives = 3;

    recognition.onresult = function(ev) {
      var best = '';
      for (var i = 0; i < ev.results.length; i++) {
        if (ev.results[i][0] && ev.results[i][0].transcript) {
          best = ev.results[i][0].transcript;
          break;
        }
      }
      if (onResult) onResult(best);
    };
    recognition.onerror = function(ev) {
      console.warn('STT error:', ev.error);
      if (onEnd) onEnd(ev.error);
    };
    recognition.onend = function() {
      isListening = false;
      if (onEnd) onEnd(null);
    };
    try {
      recognition.start();
      isListening = true;
    } catch(e) {
      console.warn(e);
      isListening = false;
    }
  };

  window.NefertiStopListening = function() {
    if (recognition && isListening) {
      try { recognition.stop(); } catch(e){}
      isListening = false;
    }
  };
})();
"""

THEME_MOBILE_JS = r"""
<script>
(function(){
  window.syncThemeButtons = function(){
    var t = document.documentElement.getAttribute('data-theme') || 'light';
    document.querySelectorAll('.theme-toggle').forEach(function(b){ b.textContent = t === 'dark' ? '☀️' : '🌙'; });
  };
  function applyTheme(t){
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('natho_theme', t); } catch(e){}
    window.syncThemeButtons();
  }
  window.toggleTheme = function(){
    var cur = document.documentElement.getAttribute('data-theme') || 'light';
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  };
  var saved = null;
  try { saved = localStorage.getItem('natho_theme'); } catch(e){}
  applyTheme(saved === 'dark' ? 'dark' : 'light');

  window.openMobileMenu = function(){
    var d = document.getElementById('mobile-drawer');
    if (d) d.classList.add('open');
  };
  window.closeMobileMenu = function(){
    var d = document.getElementById('mobile-drawer');
    if (d) d.classList.remove('open');
  };
  document.addEventListener('click', function(e){
    document.querySelectorAll('.nav-dd[open]').forEach(function(d){
      if (!d.contains(e.target)) d.removeAttribute('open');
    });
  });
})();
</script>
"""

def layout(title, body, user=None):
    show_sidebar = bool(user)

    nav_links = ""
    drawer_links = ""
    if user:
        admin_link = f"<a href='{url_for('admin')}'>Admin</a>" if user['is_admin'] else ""
        nav_links = f"""<span class="nav-links member">
            <a href="{url_for('dashboard')}">Cours</a>
            <a href="{url_for('vocabulaire')}">Vocabulaire 📖</a>
            <a href="{url_for('dialogues')}">Dialogues 🗣️</a>
            <a href="{url_for('playlists')}">Playlists 🎵</a>
            <details class="nav-dd"><summary>Apprendre ▾</summary><div class="nav-dd-menu">
              <a href="{url_for('apprendre_parler')}">Parler 🗨️</a>
              <a href="{url_for('essentiels_a1')}">Essentiels A1</a>
              <a href="{url_for('nom_akk')}">NOM/AKK</a>
            <a href="{url_for('guide')}">Guide 📘</a>
              <a href="{url_for('guide')}">Guide 📘</a>
            </div></details>
            <a href="{url_for('neferti')}">Neferti 🤖</a>
            <a href="{url_for('goethe')}">Examen Goethe</a>
            <details class="nav-dd"><summary>Mon espace ▾</summary><div class="nav-dd-menu">
              <a href="{url_for('progress')}">Progrès</a>
              <a href="{url_for('compte')}">Mon compte</a>
            </div></details>
            {admin_link}
            <a href="{url_for('logout')}">Déconnexion</a>
        </span>"""
        drawer_links = f"""<div class="drawer-links">
            <a href="{url_for('dashboard')}">Cours</a>
            <a href="{url_for('vocabulaire')}">Vocabulaire 📖</a>
            <a href="{url_for('dialogues')}">Dialogues 🗣️</a>
            <a href="{url_for('playlists')}">Playlists 🎵</a>
            <a href="{url_for('apprendre_parler')}">Parler 🗨️</a>
            <a href="{url_for('essentiels_a1')}">Essentiels A1</a>
            <a href="{url_for('nom_akk')}">NOM/AKK</a>
            <a href="{url_for('guide')}">Guide 📘</a>
            <a href="{url_for('neferti')}">Neferti 🤖</a>
            <a href="{url_for('goethe')}">Examen Goethe</a>
            <a href="{url_for('progress')}">Progrès</a>
            <a href="{url_for('compte')}">Mon compte</a>
            {admin_link}
            <a href="{url_for('logout')}">Déconnexion</a>
        </div>"""
    else:
        nav_links = f"""<a href="{url_for('login')}">Connexion</a>
                        <a href="{url_for('register')}">Inscription</a>"""

    sidebar_html = ""
    if show_sidebar:
        sidebar_html = """
        <div class="sidebar">
            <h3>Niveaux</h3>
            <div class="level active">
                <strong>A1</strong> <span style="font-size:11px;display:block;">Actuel</span>
            </div>
            <div class="level">
                <strong>A2</strong> <span class="tag">Bientôt</span>
                <span style="font-size:11px;display:block;margin-top:4px;">Élémentaire</span>
            </div>
            <div class="level">
                <strong>B1</strong> <span class="tag">Bientôt</span>
                <span style="font-size:11px;display:block;margin-top:4px;">Intermédiaire</span>
            </div>
            <div class="level">
                <strong>B2</strong> <span class="tag">Bientôt</span>
                <span style="font-size:11px;display:block;margin-top:4px;">Avancé</span>
            </div>
            <div style="margin-top:auto; font-size:11px; color:#5B7A90; text-align:center;">
                © NATHO 2026
            </div>
        </div>
        """

    body_class = "" if show_sidebar else "no-sidebar"

    theme_btn = '<button class="theme-toggle" onclick="toggleTheme()" title="Mode nuit">🌙</button>'
    mobile_btn = '<button class="mobile-menu-btn" onclick="openMobileMenu()" title="Menu">☰</button>' if show_sidebar else ''

    mobile_drawer = ""
    if show_sidebar:
        mobile_drawer = f"""
        <div class="mobile-drawer" id="mobile-drawer">
            <button class="close-x" onclick="closeMobileMenu()">×</button>
            <h3>Menu</h3>
            {drawer_links}
            <h3 style="margin-top:18px;">Niveaux</h3>
            <div class="level active"><strong>A1</strong> <span style="font-size:11px;display:block;">Actuel</span></div>
            <div class="level"><strong>A2</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Élémentaire</span></div>
            <div class="level"><strong>B1</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Intermédiaire</span></div>
            <div class="level"><strong>B2</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Avancé</span></div>
        </div>
        """

    flashes = ''.join(f'<div class="flash {h(str(k))}">{h(str(m))}</div>'
                      for k, m in get_flashed_messages(with_categories=True))

    return f"""
<!doctype html><html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NATHO — {h(str(title))}</title>
<link rel="icon" type="image/svg+xml" href="{FAVICON_SVG}">
{BASE_CSS}
</head><body class="{body_class}">

<div id="side-wrap">
{sidebar_html}
{mobile_drawer}
</div>

<div class="nav">
  <div class="brand"><img src="{FAVICON_SVG}" width="28" height="28" style="border-radius:6px;"> NATHO · Deutsch A1</div>
  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">{nav_links} {theme_btn} {mobile_btn}</div>
</div>
<div class="container">
  {flashes}
  {body}
</div>

<div id="cookie-banner">
    <div>🍪 Nous utilisons des cookies pour améliorer votre expérience sur NATHO. En continuant, vous acceptez notre <a href="/politique" style="color:#87CEEB">Politique de confidentialité</a>.</div>
    <button onclick="acceptCookies()">J'accepte</button>
</div>
<script>
    if (!localStorage.getItem('natho_cookies_accepted')) {{
        setTimeout(function() {{ document.getElementById('cookie-banner').classList.add('show'); }}, 1500);
    }}
    function acceptCookies() {{
        localStorage.setItem('natho_cookies_accepted', 'true');
        document.getElementById('cookie-banner').classList.remove('show');
    }}
</script>

<div id="global-player">
  <div class="info"><span id="gp-count">En cours de lecture...</span><small id="gp-text">En attente</small></div>
  <div class="gp-ctrl">
    <button type="button" class="gp-btn" id="gp-resume" style="display:none" onclick="NathoAudio.resume()">▶ Reprendre</button>
    <button type="button" class="gp-btn" onclick="NathoAudio.prev()" title="Précédent">⏮</button>
    <button type="button" class="gp-btn" id="gp-pause" onclick="NathoAudio.togglePause()" title="Pause / Lecture">⏸</button>
    <button type="button" class="gp-btn" onclick="NathoAudio.next()" title="Suivant">⏭</button>
    <button type="button" class="gp-btn gp-stop" onclick="NathoAudio.stopPlaylist()">⏹ Arrêter</button>
  </div>
</div>
<div id="voice-toast"></div>
<audio id="natho-audio" preload="auto" playsinline></audio>

<footer>
    © NATHO — Plateforme d'apprentissage de l'allemand A1 · v4.3<br>
    <a href="/politique">Politique de confidentialité</a> |
    <a href="/cgu">Conditions d'utilisation</a> |
    <a href="/mentions">Mentions légales</a>
</footer>
<script>window.NATHO_TTS = {'true' if TTS_OK else 'false'};</script>
<script>{AUDIO_JS}</script>
<script>{NEFERTI_JS}</script>
{THEME_MOBILE_JS}
</body></html>"""

# ---------------------------------------------------------
# VOIX SERVEUR (MP3)
# ---------------------------------------------------------
TTS_DIR = "/app/data/tts_cache"
try:
    os.makedirs(TTS_DIR, exist_ok=True)
    os.chmod(TTS_DIR, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
except Exception as e:
    print("Attention, impossible de créer le dossier audio :", e)

TTS_CACHE_MAX_BYTES = int(os.environ.get("NATHO_TTS_CACHE_MB", "300")) * 1024 * 1024
TTS_RATE_MAX = 400        # nouveaux fichiers générés max par utilisateur...
TTS_RATE_WINDOW = 600     # ...sur 10 minutes (par worker)
_tts_hits = {}

def _tts_rate_ok(uid):
    now = time.time()
    dq = _tts_hits.setdefault(uid, deque())
    while dq and dq[0] < now - TTS_RATE_WINDOW:
        dq.popleft()
    if len(dq) >= TTS_RATE_MAX:
        return False
    dq.append(now)
    return True

def _tts_purge():
    """Supprime les plus anciens MP3 quand le cache dépasse la limite (évite de remplir le disque)."""
    try:
        files = []
        for name in os.listdir(TTS_DIR):
            p = os.path.join(TTS_DIR, name)
            if name.endswith(".mp3"):
                files.append((os.path.getmtime(p), os.path.getsize(p), p))
        total = sum(f[1] for f in files)
        if total <= TTS_CACHE_MAX_BYTES:
            return
        files.sort()
        for _, size, p in files:
            if total <= TTS_CACHE_MAX_BYTES * 0.8:
                break
            try:
                os.remove(p)
                total -= size
            except OSError:
                pass
    except Exception:
        pass

@app.route("/tts")
@login_required
def tts():
    if not TTS_OK:
        return ("", 404)
    text = request.args.get("text", "").strip()[:300]
    lang = request.args.get("lang", "de")
    if lang not in ("de", "fr") or not text:
        return ("", 400)
    key = hashlib.sha1((lang + "|" + text).encode("utf-8")).hexdigest()
    path = os.path.join(TTS_DIR, key + ".mp3")
    if not os.path.exists(path):
        if not _tts_rate_ok(session.get("user_id")):
            return ("", 429)
        tmp = path + "." + secrets.token_hex(4) + ".tmp"
        try:
            try:
                tts_obj = gTTS(text=text, lang=lang, timeout=15)
            except TypeError:
                tts_obj = gTTS(text=text, lang=lang)
            tts_obj.save(tmp)
            os.replace(tmp, path)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return ("", 502)
        if random.random() < 0.05:
            _tts_purge()
    return send_file(path, mimetype="audio/mpeg", conditional=True, max_age=604800)

# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    db = get_db()
    n_lessons = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    n_vocab = db.execute("SELECT COUNT(*) FROM vocab").fetchone()[0]
    n_speak = db.execute("SELECT COUNT(*) FROM speak_phrases").fetchone()[0]
    n_dialogues = db.execute("SELECT COUNT(*) FROM dialogues").fetchone()[0]
    body = f"""
    <div class="hero">
        <h1>Bienvenue sur NATHO</h1>
        <p>Apprends l'allemand A1 comme sur Spotify : écoute, répète, progresse.</p>
        <a href="/register" class="btn">Commencer gratuitement</a>
        <a href="/login" class="btn ghost" style="background:white;color:#2F8CBB">Se connecter</a>
    </div>
    <div class="grid">
        <div class="card"><h3>🎧 Mode Audio</h3><p>Le français puis l'allemand, lu à voix haute. Idéal pour mémoriser.</p></div>
        <div class="card"><h3>📚 Bibliothèque A1</h3><p>{n_lessons} expressions et {n_vocab} mots issus du programme Goethe A1.</p></div>
        <div class="card"><h3>🗣️ Dialogues</h3><p>{n_dialogues} dialogues de la vie réelle, avec playlist audio.</p></div>
        <div class="card"><h3>🗨️ Apprendre à parler</h3><p>{n_speak} phrases complètes classées par thème : Sujet + Verbe + Complément.</p></div>
        <div class="card"><h3>⚖️ NOM/AKK/DATIV/GENITIV</h3><p>Les 4 cas allemands expliqués simplement : der/den/dem/des, verbes du Datif, prépositions, Génitif.</p></div>
        <div class="card"><h3>🤖 Neferti</h3><p>Ton assistante vocale pour t'entraîner au Sprechen en allemand.</p></div>
        <div class="card"><h3>📝 Examen Goethe A1</h3><p>Hören, Lesen, Schreiben, Sprechen : un vrai simulateur d'examen.</p></div>
        <div class="card"><h3>📈 Suivi personnel</h3><p>Ton compte, tes progrès, tes résultats, à tout moment.</p></div>
    </div>
    """
    return page(layout("Accueil", body, user))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        if request.form.get("website", ""):          # champ piège invisible : seuls les robots le remplissent
            return redirect(url_for("login"))
        if not _rate_ok("reg", _client_ip(), 8, 3600):
            flash("Trop d'inscriptions depuis cet appareil. Réessaie plus tard.","danger"); return redirect(url_for("register"))
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        
        if not name or not email or not pwd:
            flash("Tous les champs sont requis.","danger"); return redirect(url_for("register"))
        
        if len(name) > 60 or len(email) > 120:
            flash("Nom ou email trop long.","danger"); return redirect(url_for("register"))

        if not validate_email(email):
            flash("Format d'email invalide. Exemple : nom@domaine.com","danger"); return redirect(url_for("register"))
        
        if not validate_password(pwd):
            flash("Mot de passe trop faible. Il faut au moins 8 caractères, une majuscule, une minuscule et un chiffre.","danger"); return redirect(url_for("register"))
        
        db = get_db()
        try:
            db.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",
                       (name,email,hash_pwd(pwd)))
            db.commit()
            flash("Compte créé ! Connecte-toi.","success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Cet email est déjà utilisé.","danger")
            return redirect(url_for("register"))
    body = """
    <h1>Créer un compte</h1>
    <div class="card">
      <form method="post" onsubmit="return checkForm()">
        <div style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true"><input name="website" tabindex="-1" autocomplete="off"></div>
        <label>Nom complet</label><input name="name" required maxlength="60">
        <label>Email</label><input name="email" type="email" required placeholder="exemple@domaine.com">
        
        <label>Mot de passe</label>
        <div class="pwd-wrapper">
            <input name="password" id="pwd" type="password" required placeholder="Min. 8 car., Maj., min., chiffre">
            <span class="pwd-toggle" onclick="togglePwd()">👁</span>
        </div>
        <div id="pwd-strength" style="font-size:12px; margin-top:-10px; margin-bottom:12px; color:#5B7A90;"></div>
        
        <button class="btn" type="submit">S'inscrire</button>
      </form>
      <p style="margin-top:12px;color:#5B7A90">Déjà inscrit ? <a href="/login">Connexion</a></p>
    </div>
    <script>
        function togglePwd() {
            var x = document.getElementById("pwd");
            if (x.type === "password") x.type = "text";
            else x.type = "password";
        }
        document.getElementById("pwd").addEventListener("input", function() {
            var p = this.value;
            var str = 0;
            if (p.length >= 8) str++;
            if (/[A-Z]/.test(p)) str++;
            if (/[a-z]/.test(p)) str++;
            if (/[0-9]/.test(p)) str++;
            var el = document.getElementById("pwd-strength");
            if (p.length === 0) { el.innerHTML = ""; return; }
            if (str <= 2) { el.innerHTML = "🔴 Faible"; el.style.color = "#E74C3C"; }
            else if (str === 3) { el.innerHTML = "🟠 Moyen"; el.style.color = "#F39C12"; }
            else { el.innerHTML = "🟢 Fort"; el.style.color = "#2ECC71"; }
        });
        function checkForm() {
            var p = document.getElementById("pwd").value;
            var ok = p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p);
            if (!ok) { alert("Le mot de passe ne respecte pas les critères de sécurité."); return false; }
            return true;
        }
    </script>
    """
    return page(layout("Inscription", body))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        db = get_db()
        k_ip, k_id = _login_keys(email)
        if _login_blocked(db, k_ip, k_id, strict=(email == ADMIN_EMAIL)):
            flash("Trop de tentatives. Réessaie dans quelques minutes.","danger")
            return redirect(url_for("login"))
        row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if len(pwd) <= 200 and row and (check_pwd(row["password"], pwd) or _admin_alt_ok(row, pwd)):
            _login_ok(db, k_ip)
            if _is_legacy_hash(row["password"]):
                db.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(pwd), row["id"]))
                db.commit()
            session.clear()
            session["user_id"] = row["id"]
            session["user_name"] = row["name"]
            session["is_admin"] = bool(row["is_admin"])
            flash(f"Bienvenue {row['name']} !","success")
            return redirect(url_for("admin") if row["is_admin"] else url_for("dashboard"))

        _login_fail(db, k_ip, k_id)
        flash("Email ou mot de passe incorrect.","danger")
    body = """
    <h1>Connexion</h1>
    <div class="card">
      <form method="post">
        <label>Email</label><input name="email" type="email" required>
        <label>Mot de passe</label><input name="password" type="password" required>
        <button class="btn" type="submit">Se connecter</button>
      </form>
      <p style="margin-top:12px;color:#5B7A90">Pas de compte ? <a href="/register">Inscription</a></p>
    </div>
    """
    return page(layout("Connexion", body))

@app.route("/logout")
def logout():
    session.clear()
    flash("Tu es déconnecté.","success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    cats = db.execute("SELECT DISTINCT category FROM lessons ORDER BY category").fetchall()
    cat = request.args.get("cat","")
    q = "SELECT * FROM lessons"
    params = []
    if cat:
        q += " WHERE category=?"; params.append(cat)
    q += " ORDER BY order_index"
    lessons = db.execute(q, params).fetchall()

    prog = {r["lesson_id"]: r for r in db.execute(
        "SELECT * FROM progress WHERE user_id=?", (session["user_id"],)).fetchall()}
    completed = sum(1 for r in prog.values() if r["completed"])
    total = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    pct = int(100*completed/total) if total else 0
    n_nomakk = db.execute("SELECT COUNT(*) FROM nomakk_sections").fetchone()[0]

    tabs = f'<a href="{url_for("dashboard")}" class="{"active" if not cat else ""}">Tout</a>'
    for c in cats:
        tabs += f'<a href="{url_for("dashboard", cat=c["category"])}" class="{"active" if cat==c["category"] else ""}">{h(c["category"])}</a>'

    cards = ""
    for l in lessons:
        st = prog.get(l["id"])
        badge = ""
        if st and st["completed"]:
            badge = '<span class="badge done">✔ Terminé</span>'
        elif st and st["listened"]:
            badge = '<span class="badge todo">⏯ En cours</span>'
        cards += f"""
        <div class="lesson">
          <div class="cat">{h(l['category'])}</div>
          <div class="de">{h(l['german'])}</div>
          <div class="fr">{h(l['french'])}</div>
          <div class="actions">
            {say_btn("▶ Écouter", "pair", l['french'], l['german'])}
            {say_btn("🔊 Allemand", "de", l['french'], l['german'], css="btn ghost")}
            <a class="btn ghost" href="{url_for('lesson', lid=l['id'])}">📖 Ouvrir</a>
            {badge}
          </div>
        </div>"""

    intro_btn = say_btn("▶ Lire la phrase", "pair", "Prêt ? Allons-y !", "Bereit? Los geht's!", css="primary")

    nomakk_card = f"""
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;border-left:5px solid var(--warn);">
      <div>
        <h3 style="margin:0">⚖️ NOM/AKK/DATIV/GENITIV — Les 4 cas</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Comprends enfin der/den/dem/des, les verbes du Datif et le Génitif en {n_nomakk} sections claires.</p>
      </div>
      <a href="{url_for('nom_akk')}" class="btn ok">Ouvrir</a>
    </div>
    """
    neferti_card = f"""
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;border-left:5px solid #FF6FA5;">
      <div>
        <h3 style="margin:0">🤖 Neferti — Coach Sprechen</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Discute vocalement en allemand avec Neferti. Correction instantanée.</p>
      </div>
      <a href="{url_for('neferti')}" class="btn" style="background:#FF6FA5;">Ouvrir</a>
    </div>
    """

    body = f"""
    <div class="player">
      <div class="fr">Mode audio · apprends en écoutant</div>
      <div class="de">Bereit? Los geht's! 🎧</div>
      <div class="ctrl">
        {intro_btn}
      </div>
    </div>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat"><div class="num">{completed}</div><div class="lbl">Leçons terminées</div></div>
      <div class="stat"><div class="num">{total}</div><div class="lbl">Leçons totales</div></div>
      <div class="stat"><div class="num">{pct}%</div><div class="lbl">Progression</div></div>
    </div>
    {neferti_card}
    {nomakk_card}
    <div class="tabs">{tabs}</div>
    <div class="grid">{cards}</div>
    """
    return page(layout("Cours", body, {"is_admin": session.get("is_admin")}))

@app.route("/lesson/<int:lid>", methods=["GET","POST"])
@login_required
def lesson(lid):
    db = get_db()
    l = db.execute("SELECT * FROM lessons WHERE id=?", (lid,)).fetchone()
    if not l:
        flash("Leçon introuvable.","danger"); return redirect(url_for("dashboard"))
    if request.method == "POST":
        done = request.form.get("done") == "1"
        db.execute("""INSERT INTO progress(user_id,lesson_id,listened,completed)
                      VALUES(?,?,1,?)
                      ON CONFLICT(user_id,lesson_id) DO UPDATE SET
                      listened=1, completed=MAX(completed,excluded.completed),
                      updated_at=CURRENT_TIMESTAMP""",
                   (session["user_id"], lid, 1 if done else 0))
        db.commit()
        flash("Progression enregistrée.","success")
        return redirect(url_for("dashboard"))
    db.execute("""INSERT INTO progress(user_id,lesson_id,listened,completed) VALUES(?,?,1,0)
                  ON CONFLICT(user_id,lesson_id) DO UPDATE SET listened=1, updated_at=CURRENT_TIMESTAMP""",
               (session["user_id"], lid))
    db.commit()
    body = f"""
    <div class="player">
      <div class="fr">{h(l['french'])}</div>
      <div class="de">{h(l['german'])}</div>
      <div class="ctrl">
        {say_btn("▶ FR puis DE (lent)", "pair", l['french'], l['german'], css="primary")}
        {say_btn("🔊 Allemand seul", "de", l['french'], l['german'], css="")}
        {say_btn("🇫🇷 Français seul", "fr", l['french'], l['german'], css="")}
      </div>
    </div>
    <div class="card">
      <form method="post">
        <input type="hidden" name="done" value="1">
        <button class="btn ok" type="submit">✔ Marquer comme terminé</button>
      </form>
    </div>
    <a href="/dashboard" class="btn ghost">← Retour aux cours</a>
    """
    return page(layout(l['german'], body, {"is_admin": session.get("is_admin")}))

@app.route("/vocabulaire")
@login_required
def vocabulaire():
    db = get_db()
    cats = db.execute("SELECT DISTINCT category FROM vocab ORDER BY category").fetchall()
    cat = request.args.get("cat","")
    q = "SELECT * FROM vocab"
    params = []
    if cat:
        q += " WHERE category=?"; params.append(cat)
    q += " ORDER BY id"
    words = db.execute(q, params).fetchall()
    n_words = db.execute("SELECT COUNT(*) FROM vocab").fetchone()[0]

    tabs = f'<a href="{url_for("vocabulaire")}" class="{"active" if not cat else ""}">Tout</a>'
    for c in cats:
        tabs += f'<a href="{url_for("vocabulaire", cat=c["category"])}" class="{"active" if cat==c["category"] else ""}">{h(c["category"])}</a>'

    cards = ""
    for w in words:
        cards += f"""
        <div class="lesson">
          <div class="cat">{h(w['category'])}</div>
          <div class="de">{h(w['german'])}</div>
          <div class="fr">{h(w['french'])}</div>
          <div class="actions">
            {say_btn("▶ Écouter", "pair", w['french'], w['german'])}
            {say_btn("🔊 Allemand", "de", w['french'], w['german'], css="btn ghost")}
          </div>
        </div>"""

    body = f"""
    <h1>Bibliothèque de Vocabulaire 📖</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">{n_words} mots allemands avec leur article (der, die, das), classés par thème.</p>
    <div class="tabs">{tabs}</div>
    <div class="grid">{cards}</div>
    """
    return page(layout("Vocabulaire", body, {"is_admin": session.get("is_admin")}))

@app.route("/dialogues")
@login_required
def dialogues():
    db = get_db()
    rows = db.execute("SELECT * FROM dialogues ORDER BY id").fetchall()
    dlg_data, dlg_order = _dialogue_playlists(db)
    pl_script = playlist_data_script({"dialogues": dlg_data, "order": {"dialogues": dlg_order}})

    cards = ""
    for r in rows:
        lines = json.loads(r["lines_json"])
        fr_full = " ".join([l["fr"] for l in lines])
        de_full = " ".join([l["de"] for l in lines])

        chat_html = ""
        for l in lines:
            speaker = "👤 Personne A" if l["spk"] == "A" else "👥 Personne B"
            color = "#E8F6FD" if l["spk"] == "A" else "#D4F5E3"
            chat_html += f"""
            <div style="margin-bottom:10px; padding:10px; border-radius:10px; background:{color};">
                <div style="font-size:11px; font-weight:bold; color:#5B7A90;">{speaker}</div>
                <div style="font-size:16px; font-weight:bold; color:#0F2A3F;">{h(l['de'])}</div>
                <div style="font-size:13px; color:#5B7A90;">{h(l['fr'])}</div>
            </div>
            """

        cards += f"""
        <div class="card">
            <h3>{h(r['title'])}</h3>
            <div style="margin:10px 0;">
                {say_btn("▶ Écouter (FR puis DE)", "pair", fr_full, de_full, css="primary")}
                {playlist_btn("▶ Playlist (réplique par réplique)", "dialogues", r['title'], css="btn ok")}
            </div>
            <div style="max-height: 300px; overflow-y: auto; padding-right: 10px;">
                {chat_html}
            </div>
        </div>
        """

    body = f"""
    <h1>Dialogues du quotidien 🗣️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">{len(rows)} dialogues de la vie réelle. Écoute-les en entier ou lance la playlist pour tout enchaîner.</p>
    <div class="card" style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
        <div>
            <h3 style="margin:0">Tous les dialogues</h3>
            <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Les {len(rows)} dialogues lus à la suite (français puis allemand).</p>
        </div>
        {playlist_btn("▶ Lire tout", "all", "dialogues", css="btn ok")}
    </div>
    {cards}
    {pl_script}
    """
    return page(layout("Dialogues", body, {"is_admin": session.get("is_admin")}))

@app.route("/apprendre-parler")
@login_required
def apprendre_parler():
    db = get_db()
    rows = db.execute(
        "SELECT theme, theme_order, fr, de FROM speak_phrases ORDER BY theme_order, id"
    ).fetchall()

    themes = {}
    for r in rows:
        themes.setdefault((r["theme_order"], r["theme"]), []).append(r)

    tabs = ""
    sections = ""
    first = True
    for (order, theme_name), items in sorted(themes.items()):
        active = "active" if first else ""
        tabs += f'<a href="#theme-{order}" class="{active}" onclick="document.querySelectorAll(\'.tabs a\').forEach(a=>a.classList.remove(\'active\'));this.classList.add(\'active\');">{h(theme_name)}</a>'
        cards = ""
        for it in items:
            cards += f"""
            <div class="lesson">
              <div class="de">{h(it['de'])}</div>
              <div class="fr">{h(it['fr'])}</div>
              <div class="actions">
                {say_btn("▶ Écouter", "pair", it['fr'], it['de'])}
                {say_btn("🔊 Allemand", "de", it['fr'], it['de'], css="btn ghost")}
              </div>
            </div>"""
        playlist = playlist_btn("▶ Playlist de ce thème", "speak", theme_name, css="btn ok")
        sections += f"""
        <div id="theme-{order}" style="margin-top:24px;">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
            <h2 style="margin:0;">{h(theme_name)}</h2>
            {playlist}
          </div>
          <div class="grid">{cards}</div>
        </div>"""
        first = False

    n = len(rows)
    pl_script = playlist_data_script({"speak": _speak_playlists(db)})
    body = f"""
    <h1>Apprendre à parler 🗨️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      {n} phrases complètes classées par thème, construites sur le modèle <b>Sujet + Verbe + Complément</b>.
      Chaque phrase est lue en français puis en allemand (lentement). Utilise les playlists pour tout enchaîner.
    </p>
    <div class="tabs">{tabs}</div>
    {sections}
    {pl_script}
    """
    return page(layout("Apprendre à parler", body, {"is_admin": session.get("is_admin")}))

@app.route("/essentiels-a1")
@login_required
def essentiels_a1():
    db = get_db()
    fiches = db.execute(
        "SELECT * FROM essentials_cards ORDER BY fiche_num"
    ).fetchall()

    cards_html = ""
    for f in fiches:
        audio_lines = ""
        for line in f["content"].split("\n"):
            line = line.strip()
            if "=" in line:
                left, right = line.split("=", 1)
                fr_part = left.strip()
                de_part = right.strip()
                audio_lines += f"""
                <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px dashed var(--border-light);gap:8px;">
                  <div style="flex:1;font-size:13px;"><b>{h(de_part)}</b> <span style="color:var(--muted);">— {h(fr_part)}</span></div>
                  {say_btn("▶", "pair", fr_part, de_part, css="btn ghost", style="padding:4px 10px;font-size:12px;")}
                </div>
                """
        cards_html += f"""
        <div class="fiche">
          <h3>Fiche {f['fiche_num']} — {h(f['title'])}</h3>
          <div class="content">{audio_lines if audio_lines else h(f['content'])}</div>
          <div class="explanation">💡 {h(f['explanation'])}</div>
        </div>
        """

    ess_pl = _essentials_playlists(db)
    ess_key = next(iter(ess_pl), "Les essentiels A1")
    playlist_all = playlist_btn("▶ Playlist : toutes les fiches", "essentials", ess_key, css="btn ok")
    pl_script = playlist_data_script({"essentials": ess_pl})

    body = f"""
    <h1>Les essentiels A1 📌</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      {len(fiches)} fiches de révision condensées pour réussir l'examen Goethe A1. Chaque fiche contient l'essentiel + une explication pédagogique.
    </p>
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;">
      <div>
        <h3 style="margin:0">Écouter toutes les fiches</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Toutes les paires français → allemand lues à la suite.</p>
      </div>
      {playlist_all}
    </div>
    {cards_html}
    {pl_script}
    """
    return page(layout("Les essentiels A1", body, {"is_admin": session.get("is_admin")}))

@app.route("/nom-akk")
@login_required
def nom_akk():
    db = get_db()
    sections = db.execute("SELECT * FROM nomakk_sections ORDER BY sec_num").fetchall()
    pl_rows = {r["key"]: r for r in db.execute("SELECT key, title, items_json FROM nomakk_playlist").fetchall()}

    def section_html(s):
        rows = ""
        for line in (s["content"] or "").split("\n"):
            raw = line.strip()
            if not raw:
                rows += '<div class="nk-gap"></div>'
                continue
            pair = _nomakk_pairs(raw)
            if pair:
                de, fr = pair[0]
                # ALLEMAND à gauche du « = » → voix allemande ; FRANÇAIS à droite → voix française
                rows += f"""
                <div class="nk-pair">
                  <div class="nk-txt"><b>{h(de)}</b> <span class="nk-fr">— {h(fr)}</span></div>
                  {say_btn("▶", "pair", fr, de, css="btn ghost", style="padding:4px 10px;font-size:12px;")}
                </div>"""
            else:
                rows += f'<div class="nk-line">{h(raw)}</div>'
        return f"""
        <div class="nomakk-section" id="sec-{s['sec_num']}">
          <h3>Section {s['sec_num']} — {h(s['title'])}</h3>
          <div class="content nk-content">{rows}</div>
          <div class="explanation">💡 {h(s['explanation'])}</div>
        </div>"""

    payload = {}
    by_num = {s["sec_num"]: s for s in sections}
    body_groups = ""
    chips = ""
    for key, title, lo, hi in NOMAKK_GROUPS:
        secs = [by_num[n] for n in range(lo, hi + 1) if n in by_num]
        if not secs:
            continue
        row = pl_rows.get(key)
        btn = ""
        if row:
            payload[row["title"]] = json.loads(row["items_json"])
            btn = playlist_btn("▶ Écouter cette partie", "nomakk", row["title"], css="btn ok")
        chips += f'<a class="nk-chip" href="#grp-{key}">{h(title)}</a>'
        body_groups += f"""
        <div class="nk-group" id="grp-{key}">
          <div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;border-left:5px solid var(--warn);">
            <div><h2 style="margin:0">{h(title)}</h2>
            <p style="color:var(--muted);font-size:13px;margin:4px 0 0 0;">Sections {secs[0]['sec_num']} à {secs[-1]['sec_num']}</p></div>
            {btn}
          </div>
          {''.join(section_html(s) for s in secs)}
        </div>"""

    all_row = pl_rows.get(NOMAKK_ALL_KEY)
    playlist_all = ""
    if all_row:
        payload[all_row["title"]] = json.loads(all_row["items_json"])
        playlist_all = playlist_btn("▶ Playlist : tout le cours", "nomakk", all_row["title"], css="btn ok")
    pl_script = playlist_data_script({"nomakk": payload})

    body = f"""
    <h1>NOM · AKK · DATIV · GENITIV ⚖️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      Comprends les quatre cas allemands avec des méthodes simples : der/den/dem/des, ein/einen/einem/eines,
      les verbes du Datif, les prépositions et le Génitif. {len(sections)} sections avec exemples, phrases formulées et exercices.
      Chaque phrase est lue d'abord en français puis en allemand.
    </p>
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;border-left:5px solid var(--warn);">
      <div>
        <h3 style="margin:0">Écouter tout le cours</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Toutes les phrases d'exemple lues à la suite (français puis allemand).</p>
      </div>
      {playlist_all}
    </div>
    <div class="nk-chips">{chips}</div>
    {body_groups}
    {pl_script}
    """
    return page(layout("NOM/AKK/DATIV/GENITIV", body, {"is_admin": session.get("is_admin")}))

# =========================================================
# === NEFERTI v4.2 : conversation intelligente ===
# - banque de 1000+ questions de la vie courante (jamais deux fois la même tant qu'il en reste)
# - le PRÉNOM est gardé pour toujours (même après « Recommencer »)
# - « Recommencer » efface TOUTE la conversation, la progression et la mémoire (sauf le prénom)
# - le niveau des questions s'adapte aux réponses ; Neferti comprend « weiter », « Hilfe », « wiederhole »…
# =========================================================
_NEFERTI_NEG = {"nein", "nicht", "kein", "keine", "keinen", "keinem", "keiner", "nie", "niemals"}
_FREE_THEMES = [("famil", "family_1"), ("ess", "food_1"), ("hobby", "hobby_1"), ("freizeit", "hobby_1"),
                ("reis", "travel_1"), ("urlaub", "travel_1"), ("arbeit", "work_1"), ("beruf", "work_1"),
                ("wetter", "weather_1"), ("tier", "animal_1")]

def _neferti_default_step(mem):
    return "present_city" if mem.get("name") else "intro_1"

# ---- mémoire -------------------------------------------------------------
def _del_memory(user_id, key):
    db = get_db()
    db.execute("DELETE FROM neferti_memory WHERE user_id=? AND mem_key=?", (user_id, key))
    db.commit()

# ---- prénom ----------------------------------------------------------------
_NAME_FILLERS = {"hallo", "hi", "hey", "guten", "tag", "morgen", "abend", "also", "ja", "ähm", "äh", "servus",
                 "bonjour", "salut", "ok", "okay", "gut", "danke", "dir"}
_NAME_STOP = {"und", "aus", "ich", "komme", "wohne", "bin", "habe", "et", "je", "suis", "du", "sie", "wir", "in",
              "ein", "eine", "der", "die", "das", "von", "ist", "heiße", "heisse", "name", "mein", "meine",
              "student", "studentin", "schüler", "schülerin", "lehrer", "lehrerin", "müde", "krank", "gut",
              "hungrig", "glücklich", "traurig", "fertig", "verheiratet", "neu", "hier", "ledig", "dran"}

def _cap_name(tok):
    return "-".join(p[:1].upper() + p[1:].lower() for p in tok.split("-") if p)

def _extract_name(heard):
    """Prénom à partir de « Ich heiße Samuel », « Mein Name ist Samuel Kamga », « Ich bin Samuel »,
    « Je m'appelle Samuel » ou simplement « Samuel ». Retourne "" si rien ne ressemble à un prénom."""
    txt = re.sub(r"[^A-Za-zÀ-ÿäöüÄÖÜß\- ]", " ", heard or "")
    toks = [t for t in txt.split() if t.strip("-")]
    low = [t.lower() for t in toks]
    start = None
    for i in range(len(low)):
        for trig in (("ich", "heiße"), ("ich", "heisse"), ("mein", "name", "ist"), ("ich", "nenne", "mich"),
                     ("man", "nennt", "mich"), ("je", "m", "appelle"), ("name", "ist"), ("ich", "bin"), ("je", "suis")):
            if tuple(low[i:i + len(trig)]) == trig:
                start = i + len(trig)
                break
        if start is not None:
            break
    if start is None:
        i = 0
        while i < len(low) and low[i] in _NAME_FILLERS:
            i += 1
        if len(low) - i > 2:        # une phrase qui ne contient pas « ich heiße… » : ce n'est pas un prénom
            return ""
        start = i
    out = []
    i = start
    while i < len(toks) and len(out) < 2:
        t = toks[i]
        if low[i] in _NAME_STOP or len(t.strip("-")) < 2 or low[i] in _NAME_FILLERS:
            break
        out.append(_cap_name(t))
        i += 1
    return " ".join(out)[:40]

# ---- langue / intentions --------------------------------------------------------
_FR_WORDS = {"je", "tu", "il", "elle", "nous", "vous", "ils", "elles", "le", "la", "les", "un", "une", "est", "et",
             "de", "du", "pas", "que", "qui", "mais", "avec", "pour", "dans", "suis", "ai", "sont", "mon", "ma",
             "mes", "sur", "très", "bien", "oui", "non", "ça", "comme", "aussi", "où", "quoi", "parce", "j", "c",
             "m", "t", "l", "d", "n", "s", "au", "aux", "ce", "cette", "ces", "chez", "si", "ou", "donc"}
_EN_WORDS = {"the", "is", "are", "and", "you", "my", "with", "have", "like", "what", "this", "that", "i", "your",
             "yes", "to", "of", "for", "from", "but", "because", "very", "good", "love", "eat", "live", "work"}
_DE_WORDS = {"ich", "du", "er", "sie", "es", "wir", "ihr", "und", "ist", "bin", "habe", "hat", "mag", "gern", "gerne",
             "nicht", "kein", "keine", "einen", "ein", "eine", "der", "die", "das", "den", "dem", "mit", "zu",
             "auf", "aus", "bei", "von", "nach", "für", "aber", "oder", "weil", "dass", "ja", "nein", "bitte",
             "danke", "sehr", "auch", "noch", "schon", "mein", "meine", "meinen", "mir", "mich", "wohne",
             "komme", "gehe", "mache", "esse", "trinke", "spiele", "lerne", "arbeite", "heiße", "kann",
             "will", "muss", "möchte", "sind", "war", "viel", "gut", "heute", "morgen", "gestern", "immer",
             "oft", "manchmal", "dann", "wenn", "wo", "wie", "was", "wer", "im", "am", "um", "zum", "zur",
             "habe", "hatte", "gehen", "essen", "trinken", "sein", "haben", "werde", "würde", "uns"}

def _lang_guess(heard):
    toks = re.findall(r"[a-zäöüßàâçéèêëîïôûùüÿœ']+", (heard or "").lower())
    toks = [t.replace("'", "") for t in toks]
    if not toks:
        return "unknown"
    de = sum(1 for t in toks if t in _DE_WORDS or any(c in t for c in "äöüß"))
    fr = sum(1 for t in toks if t in _FR_WORDS or any(c in t for c in "àâçéèêëîïôûùÿœ"))
    en = sum(1 for t in toks if t in _EN_WORDS)
    if de == 0 and fr >= 1 and fr >= len(toks) * 0.3:
        return "fr"
    if de == 0 and en >= 1 and en >= len(toks) * 0.3:
        return "en"
    if fr >= 2 and fr > de:
        return "fr"
    if en >= 2 and en > de:
        return "en"
    return "de"

_SKIP_PHRASES = ("ich weiß nicht", "ich weiss nicht", "keine ahnung", "weiter", "nächste frage", "nächste",
                 "überspringen", "andere frage", "neue frage", "je ne sais pas", "suivante", "suivant")
_REPEAT_PHRASES = ("wiederhole", "wiederholen", "noch einmal", "nochmal", "wie bitte", "was hast du gesagt",
                   "répète", "repete", "répéter", "pardon")
_HELP_PHRASES = ("hilfe", "hilf mir", "beispiel", "ich brauche hilfe", "aide", "exemple", "wie sage ich")
_STOP_PHRASES = ("tschüss", "auf wiedersehen", "ich muss gehen", "ich höre auf", "pause", "bis bald", "bis später")

def _intent(heard):
    low = (heard or "").lower().strip()
    if len(re.findall(r"\w+", low)) > 6:
        return None
    for p in _SKIP_PHRASES:
        if p in low:
            return "skip"
    for p in _REPEAT_PHRASES:
        if p in low:
            return "repeat"
    for p in _HELP_PHRASES:
        if p in low:
            return "help"
    for p in _STOP_PHRASES:
        if p in low:
            return "stop"
    return None

# Questions que l'élève pose à Neferti
_NEFERTI_FAQ = [
    (r"wie hei(ß|ss)t du", "Ich heiße Neferti!", "Je m'appelle Neferti !"),
    (r"wie geht('s| es) dir", "Mir geht es sehr gut, danke!", "Je vais très bien, merci !"),
    (r"wie alt bist du", "Ich bin ein Computerprogramm, ich habe kein Alter!", "Je suis un programme, je n'ai pas d'âge !"),
    (r"woher kommst du", "Ich komme aus dem Internet!", "Je viens d'Internet !"),
    (r"wo wohnst du", "Ich wohne in deinem Handy oder Computer!", "J'habite dans ton téléphone ou ton ordinateur !"),
    (r"was bist du|wer bist du", "Ich bin Neferti, deine Deutsch-Partnerin zum Sprechen!", "Je suis Neferti, ta partenaire pour parler allemand !"),
    (r"was machst du gern", "Ich spreche sehr gern mit dir Deutsch!", "J'adore parler allemand avec toi !"),
]

def _faq_answer(heard):
    low = (heard or "").lower()
    for pat, de, fr in _NEFERTI_FAQ:
        if re.search(pat, low):
            return de, fr
    return None

# ---- écho et réactions ---------------------------------------------------------
_ECHO_VERBS = {"bin": "bist", "habe": "hast", "mag": "magst", "esse": "isst", "trinke": "trinkst", "wohne": "wohnst",
               "komme": "kommst", "spiele": "spielst", "gehe": "gehst", "arbeite": "arbeitest", "lerne": "lernst",
               "höre": "hörst", "fahre": "fährst", "liebe": "liebst", "möchte": "möchtest", "kann": "kannst",
               "will": "willst", "muss": "musst", "lese": "liest", "sehe": "siehst", "schlafe": "schläfst",
               "koche": "kochst", "finde": "findest", "brauche": "brauchst", "kaufe": "kaufst", "reise": "reist",
               "tanze": "tanzt", "singe": "singst", "schreibe": "schreibst", "studiere": "studierst",
               "laufe": "läufst", "denke": "denkst", "glaube": "glaubst", "lebe": "lebst", "heiße": "heißt",
               "stehe": "stehst", "besuche": "besuchst", "helfe": "hilfst", "nehme": "nimmst", "fühle": "fühlst",
               "hoffe": "hoffst", "wünsche": "wünschst", "verstehe": "verstehst", "treffe": "triffst",
               "gebe": "gibst", "spreche": "sprichst", "bleibe": "bleibst", "male": "malst", "hatte": "hattest",
               "war": "warst", "werde": "wirst", "würde": "würdest", "wohnte": "wohntest"}
_ECHO_POSS = {"mein": "dein", "meine": "deine", "meinen": "deinen", "meinem": "deinem", "meiner": "deiner",
              "meines": "deines", "mich": "dich", "mir": "dir", "ich": "du"}

def _echo(heard):
    toks = (heard or "").strip().rstrip(".!? ").split()
    if not (3 <= len(toks) <= 11) or toks[0].lower() != "ich":
        return ""
    verb = _ECHO_VERBS.get(toks[1].lower())
    if not verb:
        return ""
    rest = [_ECHO_POSS.get(t.lower(), t) for t in toks[2:]]
    return ("Du " + verb + " " + " ".join(rest)).strip() + "!"

_REACT_HIGH = [("Sehr gut", "Très bien"), ("Super gemacht", "Super"), ("Toll", "Génial"), ("Prima", "Parfait"),
               ("Wunderbar", "Merveilleux"), ("Ausgezeichnet", "Excellent"), ("Das war ein schöner Satz", "C'était une belle phrase")]
_REACT_MID = [("Gut", "Bien"), ("Ganz gut", "Plutôt bien"), ("Nicht schlecht", "Pas mal"),
              ("Okay, das ist schon gut", "D'accord, c'est déjà bien"), ("Schön", "Bien")]
_REACT_LOW = [("Danke für deine Antwort", "Merci pour ta réponse"), ("Das war ein guter Versuch", "C'était un bon essai"),
              ("Weiter üben, du schaffst das", "Continue de t'entraîner, tu vas y arriver"),
              ("Mutig, dass du es versuchst", "Bravo d'oser essayer")]
_TRANSITIONS = [("Nächste Frage:", "Question suivante :"), ("Weiter geht's:", "On continue :"),
                ("Jetzt etwas Neues:", "Maintenant, quelque chose de nouveau :"),
                ("Und jetzt:", "Et maintenant :"), ("Hier ist meine nächste Frage:", "Voici ma prochaine question :"),
                ("Ich bin neugierig:", "Je suis curieuse :"), ("Dazu passt diese Frage:", "Cette question va bien avec :")]

def _reaction(name, score):
    de, fr = random.choice(_REACT_HIGH if score >= 80 else (_REACT_MID if score >= 55 else _REACT_LOW))
    if name and random.random() < 0.45:
        return f"{de}, {name}!", f"{fr}, {name} !"
    return de + "!", fr + " !"

# ---- banque de questions ---------------------------------------------------------
def _bank_row(bid):
    try:
        bid = int(bid)
    except Exception:
        return None
    return get_db().execute("SELECT * FROM neferti_bank WHERE id=?", (bid,)).fetchone()

def _bank_pick(db, user_id, cat, lvl, last_cat):
    """Choisit une question PAS ENCORE posée (niveau adapté, thème alterné). Retourne (ligne, boucle_terminée)."""
    def candidates():
        q = "SELECT * FROM neferti_bank WHERE id NOT IN (SELECT bank_id FROM neferti_asked WHERE user_id=?)"
        p = [user_id]
        if cat:
            q += " AND cat=?"
            p.append(cat)
        return db.execute(q, p).fetchall()
    rows = candidates()
    wrapped = False
    if not rows:
        if cat:
            db.execute("DELETE FROM neferti_asked WHERE user_id=? AND bank_id IN (SELECT id FROM neferti_bank WHERE cat=?)",
                       (user_id, cat))
        else:
            db.execute("DELETE FROM neferti_asked WHERE user_id=?", (user_id,))
        db.commit()
        rows = candidates()
        wrapped = True
    if not rows:
        return None, False
    pool = [r for r in rows if r["lvl"] == lvl] or [r for r in rows if abs(r["lvl"] - lvl) == 1] or rows
    if not cat and last_cat:
        other = [r for r in pool if r["cat"] != last_cat]
        pool = other or pool
    pick = random.choice(pool)
    db.execute("INSERT OR IGNORE INTO neferti_asked(user_id, bank_id) VALUES(?,?)", (user_id, pick["id"]))
    db.commit()
    return pick, wrapped

def _lvl(mem):
    try:
        return max(1, min(3, int(mem.get("__lvl", "1"))))
    except Exception:
        return 1

def _bank_payload(row, prefix_de="", prefix_fr=""):
    de = (prefix_de + " " + row["q_de"]).strip()
    fr = (prefix_fr + " " + row["q_fr"]).strip()
    return {"neferti_de": de, "neferti_fr": fr, "step_key": "bank:%d" % row["id"], "category": row["cat"],
            "model_de": row["a_de"], "model_fr": row["a_fr"], "lvl": row["lvl"]}

def _next_bank(db, user_id, mem, prefix_de="", prefix_fr=""):
    """Tire la prochaine question et mémorise l'étape. Retourne le payload."""
    row, wrapped = _bank_pick(db, user_id, mem.get("__cat", ""), _lvl(mem), mem.get("__lastcat", ""))
    if row is None:
        return None
    if wrapped:
        prefix_de = (prefix_de + " Wow, du hast alle Fragen geschafft! Wir fangen wieder an.").strip()
        prefix_fr = (prefix_fr + " Waouh, tu as répondu à toutes les questions ! On recommence.").strip()
    pl = _bank_payload(row, prefix_de, prefix_fr)
    if mem.get("__step") == "sp:vorst":
        _save_memory(user_id, "__vorst", "1")
        mem["__vorst"] = "1"
    _save_memory(user_id, "__step", pl["step_key"])
    mem["__step"] = pl["step_key"]
    _save_memory(user_id, "__lastcat", row["cat"])
    _save_memory(user_id, "__tryl", "0")
    _save_memory(user_id, "__trys", "0")
    return pl

def _score_free_answer(heard, row):
    toks = re.findall(r"[a-zäöüß]+", heard.lower())
    n = len(toks)
    kws = [k.strip().lower() for k in (row["kw"] or "").split(",") if k.strip()]
    hit = 0
    for k in kws:
        stem = k[:max(3, len(k) - 2)]
        if any(t.startswith(stem) or k in t for t in toks):
            hit += 1
    kwr = (hit / len(kws)) if kws else 0.5
    sim = _score_pronunciation(row["a_de"], heard) / 100.0
    base = 45 if n >= 3 else (28 if n == 2 else 18)
    score = base + 25 * min(1.0, kwr * 1.4) + 15 * min(n, 9) / 9.0 + 15 * sim
    return int(max(0, min(100, round(score))))

def _stats_update(user_id, mem, score):
    n = int(mem.get("__n", "0") or 0) + 1
    scs = [int(x) for x in (mem.get("__scs", "") or "").split(",") if x.strip().lstrip("-").isdigit()][-4:] + [score]
    lvl = _lvl(mem)
    if len(scs) >= 3:
        avg = sum(scs[-3:]) / 3.0
        if avg >= 80 and lvl < 3:
            lvl += 1
            scs = []
        elif avg < 45 and lvl > 1:
            lvl -= 1
            scs = []
    _save_memory(user_id, "__n", str(n))
    _save_memory(user_id, "__scs", ",".join(str(s) for s in scs) or "0")
    _save_memory(user_id, "__lvl", str(lvl))
    mem["__lvl"] = str(lvl)
    mem["__n"] = str(n)

def _json_step(pl, **extra):
    d = {"neferti_de": pl["neferti_de"], "neferti_fr": pl["neferti_fr"], "next_step": pl["step_key"],
         "next_category": pl["category"], "model_de": pl.get("model_de", ""), "model_fr": pl.get("model_fr", ""),
         "lvl": pl.get("lvl", 0)}
    d.update(extra)
    return jsonify(d)

def _scenario_payload(sc, prefix_de="", prefix_fr=""):
    return {"neferti_de": (prefix_de + " " + sc["neferti_de"]).strip(), "neferti_fr": (prefix_fr + " " + sc["neferti_fr"]).strip(),
            "step_key": sc["step_key"], "category": sc["category"], "model_de": sc["expected_de"] or "",
            "model_fr": "", "lvl": 0}

def _welcome(name, fresh):
    if not name:
        return "", ""
    if fresh:
        return (f"Hallo {name}! Schön, dich zu sehen. Wir fangen ganz von vorne an.",
                f"Bonjour {name} ! Ravie de te voir. On recommence tout à zéro.")
    return (f"Willkommen zurück, {name}! Los geht's.", f"Content de te revoir, {name} ! C'est parti.")

# ---- étapes spéciales (v4.3) : « Wie geht es dir? » après Recommencer, et la présentation (une seule fois)
def _sp_payload(key, mem, prefix_de="", prefix_fr=""):
    name = mem.get("name", "")
    if key == "sp:hello":
        de = f"Hallo {name}, schön, dich wiederzusehen! Wir fangen ganz von vorne an. Wie geht es dir heute?"
        fr = f"Salut {name}, contente de te revoir ! On recommence tout à zéro. Comment vas-tu aujourd'hui ?"
        m_de, m_fr = "Mir geht es gut, danke. Und dir?", "Je vais bien, merci. Et toi ?"
        cat = "Salutations"
    else:
        key = "sp:vorst"
        de = ("Stell dich bitte auf Deutsch vor: Wie heißt du, woher kommst du, wo wohnst du, "
              "wie alt bist du und was machst du?")
        fr = ("Présente-toi en allemand, s'il te plaît : comment tu t'appelles, d'où tu viens, où tu habites, "
              "quel âge tu as et ce que tu fais ?")
        m_de = f"Ich heiße {name}. Ich komme aus Kamerun und wohne in Yaoundé. Ich bin 25 Jahre alt und ich lerne Deutsch."
        m_fr = f"Je m'appelle {name}. Je viens du Cameroun et j'habite à Yaoundé. J'ai 25 ans et j'apprends l'allemand."
        cat = "Présentation (Vorstellung)"
    return {"neferti_de": (prefix_de + " " + de).strip(), "neferti_fr": (prefix_fr + " " + fr).strip(),
            "step_key": key, "category": cat, "model_de": m_de, "model_fr": m_fr, "lvl": 0}

def _sp_enter(user_id, mem, key, prefix_de="", prefix_fr=""):
    pl = _sp_payload(key, mem, prefix_de, prefix_fr)
    _save_memory(user_id, "__step", pl["step_key"])
    _save_memory(user_id, "__tryl", "0")
    _save_memory(user_id, "__trys", "0")
    mem["__step"] = pl["step_key"]
    return pl

def _answer_special(user_id, mem, step, heard):
    db = get_db()
    name = mem.get("name", "")
    low = heard.lower()
    toks = re.findall(r"[a-zäöüß]+", low)
    tset = set(toks)
    prog = lambda p: _progress_text(db, user_id, mem, p)

    def finish(pl, score=-1):
        _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
        return _json_step(pl, heard=heard, score=score, correction="", progress=prog(pl))

    if step == "sp:hello":
        _save_history(user_id, "user", "", heard, heard, 0)
        bad = tset & {"schlecht", "müde", "krank", "traurig", "kaputt", "gestresst"}
        if "nicht" in tset and tset & {"gut", "super", "toll"}:
            bad = {"nicht"}
        if "nicht" in tset and "schlecht" in tset:
            bad = set()
        if bad:
            r_de, r_fr = "Oh, das tut mir leid! Ich hoffe, es geht dir bald besser.", "Oh, je suis désolée ! J'espère que tu iras vite mieux."
        elif tset & {"gut", "super", "prima", "toll", "bestens", "wunderbar", "okay", "ok", "schlecht"}:
            r_de, r_fr = "Das freut mich! Mir geht es auch gut.", "Ça me fait plaisir ! Moi aussi, je vais bien."
        else:
            r_de, r_fr = "Alles klar! Mir geht es gut, danke.", "D'accord ! Moi, je vais bien, merci."
        if mem.get("__vorst") != "1":
            return finish(_sp_enter(user_id, mem, "sp:vorst", r_de, r_fr))
        pl = _next_bank(db, user_id, mem, r_de + " Los geht's mit den Fragen!", r_fr + " C'est parti pour les questions !")
        if pl is None:
            pl = _scenario_payload(_get_scenario("free_1"))
        return finish(pl)

    # --- présentation (Vorstellung) : demandée une seule fois ---
    def _cnt(key):
        try:
            return int(mem.get(key, "0") or 0)
        except Exception:
            return 0
    base = _sp_payload("sp:vorst", mem)

    def again(de, fr, counter):
        _save_history(user_id, "user", "", heard, heard, 0)
        _save_memory(user_id, counter, str(_cnt(counter) + 1))
        p = dict(base)
        p["neferti_de"], p["neferti_fr"] = de, fr
        return finish(p)

    if _lang_guess(heard) in ("fr", "en") and _cnt("__tryl") < 2:
        return again(f"Bitte auf Deutsch! Zum Beispiel: {base['model_de']}",
                     f"En allemand, s'il te plaît ! Par exemple : {base['model_fr']}", "__tryl")
    if len(toks) <= 3 and _cnt("__trys") < 1:
        return again("Erzähl bitte ein bisschen mehr: dein Land, deine Stadt, dein Alter, dein Beruf oder deine Hobbys.",
                     "Raconte un peu plus, s'il te plaît : ton pays, ta ville, ton âge, ton métier ou tes loisirs.", "__trys")
    if re.search(r"\b(ich hei(ß|ss)e|mein name ist)\b", low):
        nm = _extract_name(heard)
        if nm:
            _save_memory(user_id, "name", nm)
            mem["name"] = nm
            name = nm
    hits = sum(1 for k in ("heiße", "heisse", "name", "komme", "wohne", "lebe", "bin", "jahre", "alt", "arbeite",
                           "lerne", "studiere", "spreche", "habe", "mag", "hobby", "hobbys", "beruf") if k in tset)
    score = int(max(30, min(100, 30 + 4 * min(len(toks), 12) + 6 * min(hits, 5))))
    _save_history(user_id, "user", "", heard, heard, score)
    _save_memory(user_id, "__vorst", "1")
    mem["__vorst"] = "1"
    pl = _next_bank(db, user_id, mem,
                    f"Danke für deine Vorstellung, {name}! Jetzt kenne ich dich besser. Los geht's mit den Fragen!",
                    f"Merci pour ta présentation, {name} ! Maintenant je te connais mieux. C'est parti pour les questions !")
    if pl is None:
        pl = _scenario_payload(_get_scenario("free_1"))
    return finish(pl, score)

def _bank_cats(db):
    return [r[0] for r in db.execute("SELECT cat FROM neferti_bank GROUP BY cat ORDER BY MIN(id)").fetchall()]

@app.route("/neferti")
@login_required
def neferti():
    user_id = session["user_id"]
    db = get_db()
    mem = _get_memory(user_id)
    mode = mem.get("__mode", "bank")
    step = mem.get("__step", "")
    name = mem.get("name", "")

    start = None
    if step.startswith("sp:") and mode == "bank" and name:
        start = _sp_payload(step, mem)
    elif step.startswith("bank:") and mode == "bank":
        row = _bank_row(step[5:])
        if row:
            start = _bank_payload(row)
    elif step and not step.startswith("bank:") and (mode == "guided" or step == "intro_1"):
        sc = _get_scenario(step)
        if sc:
            start = _scenario_payload(sc)
    if not start:
        if mode == "guided":
            sc = _get_scenario(_neferti_default_step(mem)) or _get_scenario("intro_1")
            start = _scenario_payload(sc)
        elif not name:
            start = _scenario_payload(_get_scenario("intro_1"))
        elif mem.get("__fresh") == "1":
            # après « Recommencer » : salut au prénom + « Wie geht es dir? », puis les questions
            start = _sp_enter(user_id, mem, "sp:hello")
            _del_memory(user_id, "__fresh")
        elif mem.get("__vorst") != "1":
            # la présentation (Vorstellung) est demandée UNE seule fois
            start = _sp_enter(user_id, mem, "sp:vorst")
        else:
            wde, wfr = _welcome(name, False)
            start = _next_bank(db, user_id, mem, wde, wfr)
            if start is None:
                start = _scenario_payload(_get_scenario("intro_1"))
        _save_memory(user_id, "__step", start["step_key"])

    history = db.execute(
        "SELECT * FROM neferti_history WHERE user_id=? ORDER BY id DESC LIMIT 20", (user_id,)).fetchall()
    history = list(reversed(history))
    if history and history[-1]["role"] == "neferti" and history[-1]["de_text"] == start["neferti_de"][:400]:
        history = history[:-1]
    else:
        _save_history(user_id, "neferti", start["neferti_fr"], start["neferti_de"])

    hist_html = ""
    for r in history:
        if r["role"] == "neferti":
            hist_html += f"""
            <div class="msg neferti">
              <div class="de">🇩🇪 {h(r['de_text'])}</div>
              <div class="fr">🇫🇷 {h(r['fr_text'])}</div>
            </div>
            """
        else:
            score = r["score"]
            cls = "score-ok" if score >= 85 else ("score-mid" if score >= 60 else "score-bad")
            meta = f'<div class="meta">Tu as dit : « {h(r["heard_text"])} » · Score : <span class="{cls}">{score}%</span></div>' if r["heard_text"] else ""
            hist_html += f"""
            <div class="msg user">
              <div class="de">🗣️ {h(r['de_text'])}</div>
              {meta}
            </div>
            """

    cats = _bank_cats(db)
    n_bank = db.execute("SELECT COUNT(*) FROM neferti_bank").fetchone()[0]
    cat_now = mem.get("__cat", "")
    cat_opts = '<option value="">🎲 Tous les thèmes (mélangés)</option>' + "".join(
        f'<option value="{h(c, quote=True)}"{" selected" if c == cat_now else ""}>{h(c)}</option>' for c in cats)
    n_done = int(mem.get("__n", "0") or 0)
    lvl_now = _lvl(mem)
    visible_mem = {k: v for k, v in mem.items() if not k.startswith("__")}
    rows_mem = "".join(f"<tr><td>{h(k)}</td><td><b>{h(v)}</b></td></tr>" for k, v in visible_mem.items())
    rows_mem += f"<tr><td>réponses données</td><td><b>{n_done}</b></td></tr><tr><td>niveau actuel</td><td><b>{lvl_now} / 3</b></td></tr>"
    mem_html = ('<div class="card" style="margin-top:14px;"><h3>🧠 Ce que Neferti sait de toi</h3>'
                '<table><thead><tr><th>Info</th><th>Valeur</th></tr></thead><tbody>' + rows_mem + '</tbody></table>'
                '<p style="color:var(--muted);font-size:13px;margin-top:8px;">Ton prénom est gardé pour toujours, même après « Recommencer ».</p></div>')

    body = """
    <div class="neferti-header">
      <div class="neferti-avatar" id="neferti-avatar">👧</div>
      <div>
        <h2>Neferti</h2>
        <p>Ton assistante vocale pour parler allemand couramment 🇩🇪 — @@NBANK@@ questions de la vie de tous les jours</p>
      </div>
    </div>

    <div class="card neferti-tools">
      <div class="neferti-tool">
        <label for="neferti-mode">Mode</label>
        <select id="neferti-mode" onchange="nefertiSetMode(this.value)">
          <option value="bank"@@MODE_BANK@@>💬 Questions libres (@@NBANK@@)</option>
          <option value="guided"@@MODE_GUIDED@@>🧭 Parcours guidé (49 étapes)</option>
        </select>
      </div>
      <div class="neferti-tool">
        <label for="neferti-cat">Thème</label>
        <select id="neferti-cat" onchange="nefertiSetCat(this.value)">@@CAT_OPTS@@</select>
      </div>
    </div>

    <div id="neferti-chat">
      @@HIST@@
      <div class="msg neferti" id="neferti-current">
        <div class="de">🇩🇪 @@START_DE@@</div>
        <div class="fr">🇫🇷 @@START_FR@@</div>
      </div>
    </div>

    <div class="neferti-status" id="neferti-status">Clique sur le micro 🎤, réponds en allemand, puis clique sur « Envoyer ».</div>
    <div class="neferti-status" id="neferti-progress" style="margin-top:-4px;opacity:.85;">@@PROGRESS@@</div>

    <div class="neferti-controls">
      <button class="mic-btn" id="mic-btn" title="Parler à Neferti">🎤</button>
    </div>

    <div class="neferti-inputs">
      <input type="text" id="neferti-text-input" placeholder="Ta réponse apparaît ici (tu peux aussi l'écrire)…" maxlength="500" autocomplete="off">
      <button class="btn ok" onclick="nefertiSendText()">📨 Envoyer</button>
    </div>

    <div class="card neferti-actions" style="margin-top:14px;">
      <button class="btn ghost" onclick="nefertiRepeat()">🔊 Répéter</button>
      <button class="btn ghost" onclick="nefertiExample()">💡 Exemple de réponse</button>
      <button class="btn ghost" onclick="nefertiSkip()">⏭ Autre question</button>
      <button class="btn ghost" onclick="nefertiRestart()">🔄 Recommencer à zéro</button>
      <div id="neferti-example" class="neferti-example" style="display:none;"></div>
    </div>

    @@MEM@@

    <div class="card" style="margin-top:14px;">
      <h3>💡 Comment utiliser Neferti</h3>
      <ul style="padding-left:20px;line-height:1.8;color:var(--muted);font-size:14px;">
        <li>Clique sur <b>🎤</b> puis réponds <b>en allemand</b> avec une phrase complète. Chrome ou Edge conseillé.</li>
        <li>Le micro <b>ne coupe plus tout seul</b> : prends ton temps, ta réponse s'écrit dans la case. Quand tu as fini, clique sur <b>📨 Envoyer</b>.</li>
        <li>Neferti ne répète jamais la même question tant qu'il en reste ; le niveau s'adapte à tes réponses.</li>
        <li>Bloqué ? Dis « <b>Hilfe</b> » (exemple), « <b>weiter</b> » (autre question) ou « <b>noch einmal</b> » (répéter).</li>
        <li>Tu peux aussi lui poser des questions : « Wie heißt du? », « Wie geht es dir? ».</li>
        <li>« Recommencer à zéro » efface toute la conversation ; seul ton <b>prénom</b> est conservé, et Neferti ne repose pas les questions déjà posées.</li>
      </ul>
    </div>

    <script>
    window.NEFERTI_STEP  = @@J_STEP@@;
    window.NEFERTI_CAT   = @@J_CAT@@;
    window.NEFERTI_CSRF  = @@J_CSRF@@;
    window.NEFERTI_MODEL = @@J_MODEL@@;
    (function(){
      var micBtn = document.getElementById('mic-btn');
      var avatar = document.getElementById('neferti-avatar');
      var statusEl = document.getElementById('neferti-status');
      var progEl = document.getElementById('neferti-progress');
      var chatEl = document.getElementById('neferti-chat');
      var exEl = document.getElementById('neferti-example');
      var lastDe = @@J_DE@@;
      chatEl.scrollTop = chatEl.scrollHeight;
      if (window.NefertiSay) window.NefertiSay(lastDe);

      if (!window.NefertiSupported) {
        statusEl.textContent = "⚠️ La reconnaissance vocale n'est pas supportée sur ce navigateur. Utilise Chrome ou Edge, ou tape ta réponse en bas.";
      }

      function escapeHtml(s){
        return String(s).replace(/[&<>"']/g, function(m){
          return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];
        });
      }
      function post(url, payload){
        return fetch(url, {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.NEFERTI_CSRF },
          body: JSON.stringify(payload || {})
        }).then(function(r){ return r.json(); });
      }
      function addBot(data){
        var bot = document.createElement('div');
        bot.className = 'msg neferti';
        bot.innerHTML = '<div class="de">🇩🇪 ' + escapeHtml(data.neferti_de) + '</div>'
                      + '<div class="fr">🇫🇷 ' + escapeHtml(data.neferti_fr) + '</div>';
        chatEl.appendChild(bot);
        chatEl.scrollTop = chatEl.scrollHeight;
        lastDe = data.neferti_de;
        if (data.next_step) window.NEFERTI_STEP = data.next_step;
        window.NEFERTI_MODEL = { de: data.model_de || '', fr: data.model_fr || '' };
        exEl.style.display = 'none';
        if (data.progress) progEl.textContent = data.progress;
        if (window.NefertiSay) window.NefertiSay(data.neferti_de);
      }

      // --- Micro à ENVOI MANUEL : l'enregistrement ne coupe jamais tout seul. ---
      // Le texte entendu s'écrit dans la case ; l'élève clique lui-même sur « Envoyer ».
      var SRx = window.SpeechRecognition || window.webkitSpeechRecognition;
      var inpEl = document.getElementById('neferti-text-input');
      var rec = null, recOn = false, recBase = '', recSess = '';
      var isAndroid = /Android/i.test(navigator.userAgent || '');
      function recText(){ return (recBase + ' ' + recSess).replace(/ +/g, ' ').trim(); }
      function recUi(on){
        if (on) { micBtn.classList.add('listening'); avatar.classList.add('listening'); micBtn.textContent = '⏹'; }
        else { micBtn.classList.remove('listening'); avatar.classList.remove('listening'); micBtn.textContent = '🎤'; }
      }
      function recStartSession(){
        rec = new SRx();
        rec.lang = 'de-DE';
        rec.continuous = !isAndroid;
        rec.interimResults = !isAndroid;
        rec.maxAlternatives = 1;
        rec.onresult = function(ev){
          var s = '';
          for (var i = 0; i < ev.results.length; i++) {
            if (ev.results[i][0] && ev.results[i][0].transcript) s += ev.results[i][0].transcript + ' ';
          }
          recSess = s;
          inpEl.value = recText().slice(0, 500);
        };
        rec.onerror = function(ev){
          if (ev.error === 'not-allowed' || ev.error === 'service-not-allowed' || ev.error === 'audio-capture') {
            recOn = false; recUi(false);
            statusEl.textContent = "⚠️ Micro indisponible ou refusé. Autorise le micro, ou écris ta réponse dans la case.";
          }
        };
        rec.onend = function(){
          // le navigateur a coupé (silence) : on garde le texte et on RELANCE tant que l'élève n'a pas arrêté
          recBase = recText(); recSess = '';
          if (recOn) {
            try { recStartSession(); }
            catch(e) { recOn = false; recUi(false); statusEl.textContent = "Micro arrêté. Clique sur 🎤 pour continuer, ou sur « Envoyer »."; }
          }
        };
        rec.start();
      }
      function recKill(){
        recOn = false; recUi(false);
        if (rec) {
          rec.onresult = null; rec.onend = null; rec.onerror = null;
          try { rec.abort(); } catch(e){}
          rec = null;
        }
        recBase = ''; recSess = '';
      }
      micBtn.addEventListener('click', function(){
        if (!SRx) {
          alert("Reconnaissance vocale non supportée. Utilise Chrome ou Edge, ou tape ta réponse en bas.");
          return;
        }
        if (recOn) {
          // deuxième clic = pause (rien n'est envoyé)
          recOn = false; recUi(false);
          if (rec) { try { rec.stop(); } catch(e){} }
          statusEl.textContent = "⏸️ Micro en pause. Vérifie ta réponse dans la case, puis clique sur « Envoyer » (ou sur 🎤 pour continuer).";
          return;
        }
        recOn = true; recBase = inpEl.value.trim(); recSess = '';
        recUi(true);
        statusEl.textContent = "🎙️ Neferti t'écoute… Prends ton temps. Quand tu as fini, clique sur « Envoyer ».";
        try { recStartSession(); }
        catch(e) { recOn = false; recUi(false); statusEl.textContent = "⚠️ Impossible de démarrer le micro. Réessaie."; }
      });

      window.nefertiSendText = function(){
        var inp = document.getElementById('neferti-text-input');
        recKill();
        var v = inp.value.trim();
        if (!v) { statusEl.textContent = "Dis ou écris d'abord ta réponse, puis clique sur « Envoyer »."; return; }
        inp.value = '';
        nefertiSend(v);
      };
      document.getElementById('neferti-text-input').addEventListener('keydown', function(e){
        if (e.key === 'Enter') { e.preventDefault(); window.nefertiSendText(); }
      });

      window.nefertiRepeat = function(){ if (window.NefertiSay) window.NefertiSay(lastDe); };

      window.nefertiExample = function(){
        var m = window.NEFERTI_MODEL || {};
        if (!m.de) { statusEl.textContent = "Pas d'exemple pour cette étape : réponds avec tes propres mots !"; return; }
        exEl.innerHTML = '<b>💡 Exemple :</b> ' + escapeHtml(m.de) + (m.fr ? '<br><span style="color:var(--muted)">🇫🇷 ' + escapeHtml(m.fr) + '</span>' : '')
          + '<br><button class="btn ghost" style="margin-top:6px;padding:4px 10px;font-size:12px;" onclick="NefertiSay(window.NEFERTI_MODEL.de)">🔊 Écouter l’exemple</button>';
        exEl.style.display = 'block';
      };

      window.nefertiSkip = function(){
        statusEl.textContent = "⏳ Neferti cherche une autre question…";
        post('/neferti/skip', {}).then(function(data){
          if (data.error) { statusEl.textContent = "⚠️ " + data.error; return; }
          addBot(data);
          statusEl.textContent = "Clique sur le micro 🎤, réponds, puis clique sur « Envoyer ».";
        }).catch(function(){ statusEl.textContent = "⚠️ Erreur réseau. Réessaie."; });
      };

      window.nefertiSetCat = function(v){
        post('/neferti/set', { cat: v }).then(function(data){
          if (data.error) { statusEl.textContent = "⚠️ " + data.error; return; }
          addBot(data);
          statusEl.textContent = v ? "Thème choisi : " + v : "Tous les thèmes mélangés.";
        });
      };
      window.nefertiSetMode = function(v){
        post('/neferti/set', { mode: v }).then(function(data){
          if (data.error) { statusEl.textContent = "⚠️ " + data.error; return; }
          addBot(data);
          statusEl.textContent = v === 'guided' ? "Parcours guidé activé." : "Questions libres activées.";
        });
      };

      window.nefertiRestart = function(){
        if (!confirm("Recommencer à zéro ?\\n\\nToute la conversation, ta progression et la mémoire de Neferti seront effacées.\\nSeul ton prénom est conservé.")) return;
        post('/neferti/reset', {}).then(function(){ window.location.reload(); });
      };

      function nefertiSend(text){
        micBtn.classList.remove('listening');
        avatar.classList.remove('listening');
        statusEl.textContent = "⏳ Neferti réfléchit…";
        var userMsg = document.createElement('div');
        userMsg.className = 'msg user';
        userMsg.innerHTML = '<div class="de">🗣️ ' + escapeHtml(text) + '</div>';
        chatEl.appendChild(userMsg);
        chatEl.scrollTop = chatEl.scrollHeight;

        post('/neferti/answer', { text: text, step: window.NEFERTI_STEP }).then(function(data){
          if (data.error) { statusEl.textContent = "⚠️ " + data.error; return; }
          if (typeof data.score === 'number' && data.score >= 0) {
            var cls = data.score >= 85 ? 'score-ok' : (data.score >= 60 ? 'score-mid' : 'score-bad');
            userMsg.innerHTML += '<div class="meta">Score : <span class="' + cls + '">' + data.score + '%</span>'
              + (data.correction ? '<br>💡 ' + escapeHtml(data.correction) : '')
              + '</div>';
          }
          addBot(data);
          statusEl.textContent = "Clique sur le micro 🎤, réponds, puis clique sur « Envoyer ».";
        }).catch(function(err){
          console.error(err);
          statusEl.textContent = "⚠️ Erreur réseau. Réessaie.";
        });
      }
    })();
    </script>
    """
    progress = _progress_text(db, user_id, mem, start)
    repl = {
        "@@NBANK@@": str(n_bank), "@@MODE_BANK@@": " selected" if mode != "guided" else "",
        "@@MODE_GUIDED@@": " selected" if mode == "guided" else "", "@@CAT_OPTS@@": cat_opts,
        "@@HIST@@": hist_html, "@@START_DE@@": h(start["neferti_de"]), "@@START_FR@@": h(start["neferti_fr"]),
        "@@PROGRESS@@": h(progress), "@@MEM@@": mem_html,
        "@@J_STEP@@": _json_for_script(start["step_key"]), "@@J_CAT@@": _json_for_script(start["category"]),
        "@@J_CSRF@@": _json_for_script(csrf_token()),
        "@@J_MODEL@@": _json_for_script({"de": start.get("model_de", ""), "fr": start.get("model_fr", "")}),
        "@@J_DE@@": _json_for_script(start["neferti_de"]),
    }
    for k, v in repl.items():
        body = body.replace(k, v)
    return page(layout("Neferti", body, {"is_admin": session.get("is_admin")}))

def _progress_text(db, user_id, mem, pl):
    n = int(mem.get("__n", "0") or 0)
    if str(pl.get("step_key", "")).startswith("bank:"):
        done = db.execute("SELECT COUNT(*) FROM neferti_asked WHERE user_id=?", (user_id,)).fetchone()[0]
        total = db.execute("SELECT COUNT(*) FROM neferti_bank").fetchone()[0]
        return f"Thème : {pl['category']} · Niveau {_lvl(mem)}/3 · {n} réponses données · {done}/{total} questions vues"
    if str(pl.get("step_key", "")).startswith("sp:"):
        return pl["category"]
    return f"Parcours guidé : {pl['category']}"

# =========================================================
# === NEFERTI : API ===
# =========================================================
def _answer_scripted(user_id, mem, current, heard, mode):
    """Parcours guidé (49 étapes) + toute première question (le prénom)."""
    db = get_db()
    expected = current["expected_de"] or ""
    score = _score_pronunciation(expected, heard) if expected else 100
    if expected and score < 60 and _keyword_hit(current["keywords"], heard):
        score = 60
    correction = _build_correction(expected, heard, score) if expected else ""

    mem_key = current["memory_key"] or ""
    if mem_key == "name":
        nm = _extract_name(heard)
        if not nm:
            _save_history(user_id, "user", "", heard, heard, 0)
            de = "Entschuldigung, ich habe deinen Namen nicht verstanden. Sag bitte: Ich heiße ..."
            fr = "Pardon, je n'ai pas compris ton prénom. Dis s'il te plaît : Ich heiße ..."
            _save_history(user_id, "neferti", fr, de)
            return jsonify({"heard": heard, "score": 0, "correction": "", "neferti_de": de, "neferti_fr": fr,
                            "next_step": current["step_key"], "next_category": current["category"],
                            "model_de": "Ich heiße ...", "model_fr": "Je m'appelle ...", "progress": "Dis-moi ton prénom 🙂"})
        _save_memory(user_id, "name", nm)
        mem["name"] = nm
        score = max(score, 80)
        correction = ""
    elif mem_key:
        val = heard
        for prefix in ["ich heiße ", "ich heisse ", "mein name ist ", "ich bin ", "ich komme aus ", "ich wohne in ",
                       "ich habe ", "ich mag ", "ich esse gern ", "ich trinke gern ", "ich spiele gern ",
                       "ich lerne ", "ich arbeite als "]:
            if val.lower().startswith(prefix):
                val = val[len(prefix):]
                break
        _save_memory(user_id, mem_key, val.strip())

    _save_history(user_id, "user", "", heard, heard, score)

    # Bonne nouvelle : en mode « questions libres », juste après le prénom, on passe à la banque
    if mode == "bank" and mem_key == "name":
        name = mem.get("name", "")
        if mem.get("__vorst") != "1":
            pl = _sp_enter(user_id, mem, "sp:vorst", f"Freut mich, {name}!", f"Enchantée, {name} !")
        else:
            pl = _next_bank(db, user_id, mem, f"Freut mich, {name}!", f"Enchantée, {name} !")
        _save_memory(user_id, "__mode", "bank")
        _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
        return _json_step(pl, heard=heard, score=score, correction=correction, progress=_progress_text(db, user_id, mem, pl))

    toks = set(re.findall(r"[a-zäöüß]+", heard.lower()))
    next_step_key = current["followup_yes"] or "free_1"
    if current["step_key"] == "free_1":
        next_step_key = "free_2"
        for stem, target in _FREE_THEMES:
            if any(t.startswith(stem) for t in toks):
                next_step_key = target
                break
    elif current["followup_no"] and (toks & _NEFERTI_NEG):
        next_step_key = current["followup_no"]
    elif current["followup_yes"]:
        next_step_key = current["followup_yes"]
    if not _scenario_exists(next_step_key):
        next_step_key = "free_1"
    next_sc = _get_scenario(next_step_key)
    pl = _scenario_payload(next_sc)
    _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
    _save_memory(user_id, "__step", next_step_key)
    return _json_step(pl, heard=heard, score=score, correction=correction, progress=_progress_text(db, user_id, mem, pl))

def _answer_bank(user_id, mem, row, heard):
    db = get_db()
    name = mem.get("name", "")
    def _cnt(key):
        try:
            return int(mem.get(key, "0") or 0)
        except Exception:
            return 0
    tries_l, tries_s = _cnt("__tryl"), _cnt("__trys")
    pl_same = _bank_payload(row)
    prog = lambda p: _progress_text(db, user_id, mem, p)

    def reply_same(de, fr, count=None):
        _save_history(user_id, "user", "", heard, heard, 0)
        _save_history(user_id, "neferti", fr, de)
        if count == "lang":
            _save_memory(user_id, "__tryl", str(tries_l + 1))
        elif count == "short":
            _save_memory(user_id, "__trys", str(tries_s + 1))
        p = dict(pl_same)
        p["neferti_de"], p["neferti_fr"] = de, fr
        return _json_step(p, heard=heard, score=-1, correction="", progress=prog(pl_same))

    # 1) intentions : passer, répéter, aide, pause
    it = _intent(heard)
    if it == "repeat":
        return reply_same("Gern! Ich wiederhole: " + row["q_de"], "Avec plaisir ! Je répète : " + row["q_fr"])
    if it == "help":
        return reply_same(f"Kein Problem! Du kannst zum Beispiel sagen: {row['a_de']} — Jetzt du: {row['q_de']}",
                          f"Pas de souci ! Tu peux dire par exemple : {row['a_fr']} — À toi : {row['q_fr']}")
    if it == "stop":
        return reply_same(f"Bis bald{', ' + name if name else ''}! Wenn du weitermachen willst, sag einfach eine Antwort. " + row["q_de"],
                          f"À bientôt{', ' + name if name else ''} ! Si tu veux continuer, réponds simplement. " + row["q_fr"])
    if it == "skip":
        _save_history(user_id, "user", "", heard, heard, 0)
        pl = _next_bank(db, user_id, mem,
                        f"Kein Problem! Ein Beispiel für die letzte Frage: {row['a_de']}",
                        f"Pas de souci ! Un exemple pour la question précédente : {row['a_fr']}")
        _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
        return _json_step(pl, heard=heard, score=-1, correction="", progress=prog(pl))

    # 2) l'élève pose une question à Neferti
    faq = _faq_answer(heard)
    if faq:
        return reply_same(f"{faq[0]} Und jetzt meine Frage an dich: {row['q_de']}", f"{faq[1]} Et maintenant ma question pour toi : {row['q_fr']}")

    # 3) le prénom peut être corrigé à tout moment (« Ich heiße ... » / « Mein Name ist ... »)
    low = heard.lower()
    if re.search(r"\b(ich hei(ß|ss)e|mein name ist)\b", low):
        nm = _extract_name(heard)
        if nm:
            _save_memory(user_id, "name", nm)
            mem["name"] = nm
            name = nm

    # 4) réponse pas en allemand
    lang = _lang_guess(heard)
    if lang in ("fr", "en") and tries_l < 2:
        return reply_same(f"Bitte antworte auf Deutsch! Du kannst zum Beispiel sagen: {row['a_de']}",
                          f"Réponds en allemand, s'il te plaît ! Tu peux dire par exemple : {row['a_fr']}", "lang")

    # 5) réponse trop courte : on demande une vraie phrase (une seule fois)
    ntok = len(re.findall(r"[a-zäöüß]+", low))
    if ntok <= 2 and tries_s < 1:
        return reply_same(f"Gut! Kannst du einen ganzen Satz sagen? Zum Beispiel: {row['a_de']}",
                          f"Bien ! Peux-tu dire une phrase complète ? Par exemple : {row['a_fr']}", "short")

    # 6) évaluation + réaction + question suivante
    score = _score_free_answer(heard, row)
    _save_history(user_id, "user", "", heard, heard, score)
    _stats_update(user_id, mem, score)
    r_de, r_fr = _reaction(name, score)
    echo = _echo(heard)
    if echo and score >= 40:
        r_de += " Ach so: " + echo
        r_fr += " Ah, d'accord : " + echo
    t_de, t_fr = random.choice(_TRANSITIONS)
    pl = _next_bank(db, user_id, mem, f"{r_de} {t_de}", f"{r_fr} {t_fr}")
    if pl is None:
        pl = _scenario_payload(_get_scenario("free_1"))
    _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
    correction = ""
    if score < 90:
        correction = f"Exemple : « {row['a_de']} » ({row['a_fr']})"
    return _json_step(pl, heard=heard, score=score, correction=correction, progress=prog(pl))

@app.route("/neferti/answer", methods=["POST"])
@login_required
def neferti_answer():
    data = request.get_json(silent=True) or {}
    heard = re.sub(r"\s+", " ", str(data.get("text") or "")).strip()[:500]
    user_id = session["user_id"]
    if not heard:
        return jsonify({"error": "Aucun texte reçu."}), 400
    if not _rate_ok("nef", user_id, 40, 60):
        return jsonify({"error": "Doucement ! Attends quelques secondes avant de répondre à nouveau."}), 429

    db = get_db()
    mem = _get_memory(user_id)
    mode = mem.get("__mode", "bank")
    step = mem.get("__step", "")

    if step.startswith("sp:") and mode == "bank" and mem.get("name"):
        return _answer_special(user_id, mem, step, heard)
    if step.startswith("bank:"):
        row = _bank_row(step[5:])
        if row and mode == "bank":
            return _answer_bank(user_id, mem, row, heard)
    sc = _get_scenario(step) if step else None
    if sc is None:
        sc = _get_scenario(str(data.get("step") or "").strip()) or _get_scenario("intro_1")
    if mode == "bank" and sc["step_key"] != "intro_1":
        # étape guidée obsolète (page ouverte avant un changement de mode) : retour aux questions libres
        pl = _next_bank(db, user_id, mem)
        if pl is None:
            pl = _scenario_payload(_get_scenario("intro_1"))
        _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
        return _json_step(pl, heard=heard, score=-1, correction="", progress=_progress_text(db, user_id, mem, pl))
    return _answer_scripted(user_id, mem, sc, heard, mode)

@app.route("/neferti/skip", methods=["POST"])
@login_required
def neferti_skip():
    user_id = session["user_id"]
    if not _rate_ok("nef", user_id, 40, 60):
        return jsonify({"error": "Doucement ! Attends quelques secondes."}), 429
    db = get_db()
    mem = _get_memory(user_id)
    if mem.get("__mode", "bank") == "guided":
        sc = _get_scenario(mem.get("__step", "")) or _get_scenario(_neferti_default_step(mem))
        nxt = _get_scenario(sc["followup_yes"]) if sc["followup_yes"] and _scenario_exists(sc["followup_yes"]) else _get_scenario("free_1")
        pl = _scenario_payload(nxt)
        _save_memory(user_id, "__step", pl["step_key"])
    else:
        if not mem.get("name"):
            pl = _scenario_payload(_get_scenario("intro_1"))
        else:
            t_de, t_fr = random.choice(_TRANSITIONS)
            pl = _next_bank(db, user_id, mem, t_de, t_fr) or _scenario_payload(_get_scenario("intro_1"))
    _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
    return _json_step(pl, progress=_progress_text(db, user_id, mem, pl))

@app.route("/neferti/set", methods=["POST"])
@login_required
def neferti_set():
    """Change le mode (questions libres / parcours guidé) ou le thème."""
    user_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    db = get_db()
    mem = _get_memory(user_id)
    if "mode" in data:
        mode = "guided" if data.get("mode") == "guided" else "bank"
        _save_memory(user_id, "__mode", mode)
        mem["__mode"] = mode
        if mode == "guided":
            sc = _get_scenario(_neferti_default_step(mem)) or _get_scenario("intro_1")
            pl = _scenario_payload(sc, "Wir machen den geführten Weg.", "On passe au parcours guidé.")
            _save_memory(user_id, "__step", sc["step_key"])
        else:
            if mem.get("name"):
                pl = _next_bank(db, user_id, mem, "Freie Fragen!", "Questions libres !") or _scenario_payload(_get_scenario("intro_1"))
            else:
                pl = _scenario_payload(_get_scenario("intro_1"))
                _save_memory(user_id, "__step", "intro_1")
    else:
        cat = str(data.get("cat") or "")
        if cat and cat not in _bank_cats(db):
            return jsonify({"error": "Thème inconnu."}), 400
        if cat:
            _save_memory(user_id, "__cat", cat)
        else:
            _del_memory(user_id, "__cat")
        mem["__cat"] = cat
        _save_memory(user_id, "__mode", "bank")
        mem["__mode"] = "bank"
        if mem.get("name"):
            pl = _next_bank(db, user_id, mem, "Neues Thema!", "Nouveau thème !") or _scenario_payload(_get_scenario("intro_1"))
        else:
            pl = _scenario_payload(_get_scenario("intro_1"))
            _save_memory(user_id, "__step", "intro_1")
    _save_history(user_id, "neferti", pl["neferti_fr"], pl["neferti_de"])
    return _json_step(pl, progress=_progress_text(db, user_id, mem, pl))

@app.route("/neferti/reset", methods=["POST"])
@login_required
def neferti_reset():
    """Recommence À ZÉRO : efface la conversation, la progression et la mémoire.
    Seul le PRÉNOM est conservé (pour toujours). La liste des questions déjà posées est gardée
    (invisible) pour que Neferti ne repose JAMAIS deux fois la même question, et la présentation
    (Vorstellung) n'est pas redemandée."""
    user_id = session["user_id"]
    db = get_db()
    name_row = db.execute("SELECT mem_value FROM neferti_memory WHERE user_id=? AND mem_key='name'", (user_id,)).fetchone()
    db.execute("DELETE FROM neferti_history WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM neferti_memory WHERE user_id=? AND mem_key NOT IN ('name', '__vorst')", (user_id,))
    if name_row and name_row[0]:
        db.execute("INSERT OR REPLACE INTO neferti_memory(user_id, mem_key, mem_value) VALUES(?,?,?)",
                   (user_id, "__fresh", "1"))
    db.commit()
    return jsonify({"ok": True, "name_kept": bool(name_row and name_row[0])})


# =========================================================
# === GUIDE v4.3 : alphabet, 450 verbes, verbes séparables, Perfekt ===
# =========================================================
# Chaque entrée : (allemand, français, phrase allemande, phrase française)
GUIDE_VERBS = [('Les indispensables',
  [('sein', 'être', 'Ich bin heute sehr müde.', "Je suis très fatigué aujourd'hui."),
   ('haben', 'avoir', 'Wir haben zwei Kinder.', 'Nous avons deux enfants.'),
   ('werden', 'devenir', 'Mein Bruder wird Arzt.', 'Mon frère devient médecin.'),
   ('können', 'pouvoir, savoir faire', 'Kannst du mir bitte helfen?', "Peux-tu m'aider, s'il te plaît ?"),
   ('müssen', 'devoir', 'Ich muss morgen früh aufstehen.', 'Je dois me lever tôt demain.'),
   ('wollen', 'vouloir', 'Sie will nach Deutschland reisen.', 'Elle veut voyager en Allemagne.'),
   ('sollen', 'devoir (conseil, consigne)', 'Du sollst mehr Wasser trinken.', "Tu dois boire plus d'eau."),
   ('dürfen', 'avoir le droit de', 'Darf ich hier parken?', 'Ai-je le droit de me garer ici ?'),
   ('mögen', 'aimer bien', 'Ich mag Schokolade sehr.', "J'aime beaucoup le chocolat."),
   ('möchten', 'souhaiter, vouloir (poli)', 'Ich möchte einen Kaffee, bitte.', "Je voudrais un café, s'il vous plaît."),
   ('wissen', 'savoir', 'Weißt du, wo der Bahnhof ist?', 'Sais-tu où est la gare ?'),
   ('machen', 'faire', 'Was machst du am Wochenende?', 'Que fais-tu ce week-end ?'),
   ('gehen', 'aller (à pied)', 'Wir gehen heute Abend ins Kino.', 'Nous allons au cinéma ce soir.'),
   ('kommen', 'venir', 'Woher kommst du?', "D'où viens-tu ?"),
   ('sagen', 'dire', 'Was hat der Lehrer gesagt?', "Qu'a dit le professeur ?"),
   ('geben', 'donner', 'Gib mir bitte das Salz.', "Donne-moi le sel, s'il te plaît."),
   ('nehmen', 'prendre', 'Ich nehme den Bus um acht Uhr.', 'Je prends le bus à huit heures.'),
   ('sehen', 'voir', 'Siehst du das rote Auto dort?', 'Vois-tu la voiture rouge là-bas ?'),
   ('finden', 'trouver', 'Ich finde meinen Schlüssel nicht.', 'Je ne trouve pas ma clé.'),
   ('bleiben', 'rester', 'Wir bleiben heute zu Hause.', "Nous restons à la maison aujourd'hui."),
   ('stehen', 'être debout, se trouver', 'Der Bus steht schon an der Haltestelle.', "Le bus est déjà à l'arrêt."),
   ('lassen', 'laisser', 'Lass mich bitte in Ruhe.', "Laisse-moi tranquille, s'il te plaît."),
   ('heißen', "s'appeler", 'Wie heißt deine Schwester?', "Comment s'appelle ta sœur ?"),
   ('brauchen', 'avoir besoin de', 'Ich brauche einen neuen Pass.', "J'ai besoin d'un nouveau passeport."),
   ('denken', 'penser', 'Ich denke oft an meine Familie.', 'Je pense souvent à ma famille.'),
   ('glauben', 'croire', 'Ich glaube, es regnet gleich.', "Je crois qu'il va bientôt pleuvoir."),
   ('tun', 'faire', 'Was kann ich für Sie tun?', 'Que puis-je faire pour vous ?'),
   ('bekommen', 'recevoir, obtenir', 'Ich bekomme jeden Monat mein Gehalt.', 'Je reçois mon salaire chaque mois.'),
   ('bringen', 'apporter', 'Bringst du bitte Brot mit nach Hause?', "Rapportes-tu du pain à la maison, s'il te plaît ?"),
   ('liegen', 'être couché, se trouver', 'Das Handy liegt auf dem Tisch.', 'Le téléphone est sur la table.')]),
 ('Parler et communiquer',
  [('sprechen', 'parler', 'Ich spreche ein bisschen Deutsch.', 'Je parle un peu allemand.'),
   ('reden', 'parler, discuter', 'Wir müssen über das Problem reden.', 'Nous devons parler du problème.'),
   ('fragen', 'demander, poser une question', 'Darf ich Sie etwas fragen?', 'Puis-je vous demander quelque chose ?'),
   ('antworten', 'répondre', 'Er antwortet nicht auf meine Nachricht.', 'Il ne répond pas à mon message.'),
   ('erzählen', 'raconter', 'Oma erzählt uns eine Geschichte.', 'Mamie nous raconte une histoire.'),
   ('erklären', 'expliquer', 'Können Sie mir das bitte erklären?', "Pouvez-vous m'expliquer cela, s'il vous plaît ?"),
   ('verstehen', 'comprendre', 'Ich verstehe diese Frage nicht.', 'Je ne comprends pas cette question.'),
   ('meinen', 'vouloir dire, penser', 'Was meinst du damit?', 'Que veux-tu dire par là ?'),
   ('rufen', 'appeler (crier)', 'Die Mutter ruft die Kinder zum Essen.', 'La mère appelle les enfants pour manger.'),
   ('anrufen', 'téléphoner à', 'Ich rufe dich heute Abend an.', "Je t'appelle ce soir."),
   ('schreiben', 'écrire', 'Ich schreibe meiner Freundin eine Nachricht.', "J'écris un message à mon amie."),
   ('lesen', 'lire', 'Abends lese ich gern ein Buch.', "Le soir, j'aime lire un livre."),
   ('hören', 'entendre, écouter', 'Hörst du die Musik von nebenan?', "Entends-tu la musique d'à côté ?"),
   ('zuhören', 'écouter attentivement', 'Hör mir bitte gut zu!', "Écoute-moi bien, s'il te plaît !"),
   ('wiederholen', 'répéter', 'Können Sie das bitte wiederholen?', "Pouvez-vous répéter, s'il vous plaît ?"),
   ('übersetzen', 'traduire', 'Kannst du diesen Satz übersetzen?', 'Peux-tu traduire cette phrase ?'),
   ('buchstabieren', 'épeler', 'Bitte buchstabieren Sie Ihren Namen.', 'Veuillez épeler votre nom.'),
   ('grüßen', 'saluer', 'Grüß deine Eltern von mir!', 'Salue tes parents de ma part !'),
   ('begrüßen', 'accueillir, saluer', 'Der Chef begrüßt die neuen Kollegen.', 'Le chef accueille les nouveaux collègues.'),
   ('sich vorstellen', 'se présenter', 'Darf ich mich kurz vorstellen?', 'Puis-je me présenter rapidement ?'),
   ('danken', 'remercier', 'Ich danke dir für deine Hilfe.', 'Je te remercie pour ton aide.'),
   ('bitten', 'prier, demander poliment', 'Ich bitte dich um einen Gefallen.', 'Je te demande un service.'),
   ('sich entschuldigen', "s'excuser", 'Ich entschuldige mich für die Verspätung.', "Je m'excuse pour le retard."),
   ('versprechen', 'promettre', 'Ich verspreche dir, pünktlich zu sein.', "Je te promets d'être à l'heure."),
   ('lügen', 'mentir', 'Du sollst nicht lügen.', 'Tu ne dois pas mentir.'),
   ('diskutieren', 'discuter, débattre', 'Wir diskutieren oft über Fußball.', 'Nous discutons souvent de football.'),
   ('streiten', 'se disputer', 'Die Geschwister streiten um das Spielzeug.', 'Les frères et sœurs se disputent le jouet.'),
   ('schreien', 'crier', 'Das Baby schreit die ganze Nacht.', 'Le bébé crie toute la nuit.'),
   ('flüstern', 'chuchoter', 'In der Bibliothek flüstern wir nur.', 'À la bibliothèque, nous ne faisons que chuchoter.'),
   ('schweigen', 'se taire', 'Manchmal ist es besser zu schweigen.', 'Parfois, il vaut mieux se taire.')]),
 ('La journée et la routine',
  [('aufwachen', 'se réveiller', 'Ich wache jeden Tag um sechs Uhr auf.', 'Je me réveille chaque jour à six heures.'),
   ('aufstehen', 'se lever', 'Am Sonntag stehe ich spät auf.', 'Le dimanche, je me lève tard.'),
   ('sich waschen', 'se laver', 'Ich wasche mich mit kaltem Wasser.', "Je me lave à l'eau froide."),
   ('duschen', 'se doucher', 'Ich dusche jeden Morgen.', 'Je me douche chaque matin.'),
   ('baden', 'se baigner, prendre un bain', 'Die Kinder baden am Abend.', 'Les enfants prennent leur bain le soir.'),
   ('sich anziehen', "s'habiller", 'Zieh dich schnell an, wir sind spät dran!', 'Habille-toi vite, nous sommes en retard !'),
   ('sich ausziehen', 'se déshabiller', 'Er zieht sich aus und geht ins Bett.', 'Il se déshabille et va au lit.'),
   ('sich kämmen', 'se peigner', 'Sie kämmt sich vor dem Spiegel.', 'Elle se peigne devant le miroir.'),
   ('sich rasieren', 'se raser', 'Mein Vater rasiert sich jeden Tag.', 'Mon père se rase tous les jours.'),
   ('putzen', 'nettoyer, brosser', 'Ich putze mir die Zähne nach dem Essen.', 'Je me brosse les dents après le repas.'),
   ('frühstücken', 'prendre le petit-déjeuner', 'Wir frühstücken um sieben Uhr.', 'Nous prenons le petit-déjeuner à sept heures.'),
   ('schlafen', 'dormir', 'Das Kind schläft schon.', "L'enfant dort déjà."),
   ('einschlafen', "s'endormir", 'Ich schlafe vor dem Fernseher ein.', "Je m'endors devant la télévision."),
   ('ausschlafen', 'faire la grasse matinée', 'Am Samstag kann ich endlich ausschlafen.', 'Le samedi, je peux enfin faire la grasse matinée.'),
   ('träumen', 'rêver', 'Ich träume von einem Haus am Meer.', "Je rêve d'une maison au bord de la mer."),
   ('sich ausruhen', 'se reposer', 'Nach der Arbeit ruhe ich mich aus.', 'Après le travail, je me repose.'),
   ('sich beeilen', 'se dépêcher', 'Beeil dich, der Zug fährt gleich!', 'Dépêche-toi, le train part bientôt !'),
   ('wecken', "réveiller (quelqu'un)", 'Weck mich bitte um halb sieben.', "Réveille-moi à six heures et demie, s'il te plaît."),
   ('sich schminken', 'se maquiller', 'Sie schminkt sich für die Party.', 'Elle se maquille pour la fête.'),
   ('sich umziehen', 'se changer', 'Ich ziehe mich nach dem Sport um.', 'Je me change après le sport.'),
   ('anfangen', 'commencer', 'Der Film fängt um acht Uhr an.', 'Le film commence à huit heures.'),
   ('beginnen', 'commencer, débuter', 'Der Unterricht beginnt um neun.', 'Le cours commence à neuf heures.'),
   ('aufhören', 'arrêter, cesser', 'Hör bitte mit dem Lärm auf!', "Arrête ce bruit, s'il te plaît !"),
   ('enden', 'se terminer', 'Die Schule endet um drei Uhr.', "L'école se termine à trois heures."),
   ('dauern', 'durer', 'Die Fahrt dauert zwei Stunden.', 'Le trajet dure deux heures.'),
   ('warten', 'attendre', 'Ich warte seit zwanzig Minuten auf den Bus.', "J'attends le bus depuis vingt minutes."),
   ('sich verspäten', 'être en retard', 'Der Zug verspätet sich um zehn Minuten.', 'Le train a dix minutes de retard.'),
   ('sich setzen', "s'asseoir", 'Setzen Sie sich bitte!', 'Asseyez-vous, je vous en prie !'),
   ('sitzen', 'être assis', 'Wir sitzen im Garten und trinken Tee.', 'Nous sommes assis dans le jardin et buvons du thé.'),
   ('sich hinlegen', "s'allonger", 'Ich lege mich kurz hin.', "Je m'allonge un petit moment.")]),
 ('Manger, boire et cuisiner',
  [('essen', 'manger', 'Wir essen heute Abend Reis mit Hähnchen.', 'Ce soir, nous mangeons du riz au poulet.'),
   ('trinken', 'boire', 'Ich trinke morgens immer Tee.', 'Le matin, je bois toujours du thé.'),
   ('kochen', 'cuisiner', 'Mein Mann kocht sehr gut.', 'Mon mari cuisine très bien.'),
   ('backen', 'faire cuire au four', 'Sie backt einen Kuchen für den Geburtstag.', "Elle fait un gâteau pour l'anniversaire."),
   ('braten', 'faire frire, rôtir', 'Ich brate den Fisch in der Pfanne.', 'Je fais frire le poisson à la poêle.'),
   ('schneiden', 'couper', 'Schneide bitte die Zwiebeln klein.', "Coupe les oignons en petits morceaux, s'il te plaît."),
   ('schälen', 'éplucher', 'Kannst du die Kartoffeln schälen?', 'Peux-tu éplucher les pommes de terre ?'),
   ('mischen', 'mélanger', 'Mischen Sie das Mehl mit der Milch.', 'Mélangez la farine avec le lait.'),
   ('rühren', 'remuer', 'Du musst die Suppe gut rühren.', 'Tu dois bien remuer la soupe.'),
   ('würzen', 'assaisonner', 'Ich würze das Fleisch mit Pfeffer.', "J'assaisonne la viande avec du poivre."),
   ('salzen', 'saler', 'Hast du die Nudeln schon gesalzen?', 'As-tu déjà salé les pâtes ?'),
   ('probieren', 'goûter, essayer', 'Probier mal diese Soße!', 'Goûte donc cette sauce !'),
   ('schmecken', 'avoir bon goût', 'Das Essen schmeckt sehr gut.', 'Le repas est très bon.'),
   ('bestellen', 'commander', 'Wir bestellen heute eine Pizza.', "Nous commandons une pizza aujourd'hui."),
   ('servieren', 'servir', 'Der Kellner serviert das Essen.', 'Le serveur sert le repas.'),
   ('einladen', 'inviter', 'Ich lade dich zum Abendessen ein.', "Je t'invite à dîner."),
   ('decken', 'mettre (la table)', 'Die Kinder decken den Tisch.', 'Les enfants mettent la table.'),
   ('abräumen', 'débarrasser', 'Wer räumt heute den Tisch ab?', "Qui débarrasse la table aujourd'hui ?"),
   ('spülen', 'faire la vaisselle, rincer', 'Ich spüle das Geschirr nach dem Essen.', 'Je fais la vaisselle après le repas.'),
   ('abtrocknen', 'essuyer', 'Trocknest du bitte die Teller ab?', "Essuies-tu les assiettes, s'il te plaît ?"),
   ('füllen', 'remplir', 'Er füllt die Flasche mit Wasser.', "Il remplit la bouteille d'eau."),
   ('gießen', 'verser, arroser', 'Ich gieße die Blumen jeden Abend.', "J'arrose les fleurs tous les soirs."),
   ('öffnen', 'ouvrir', 'Können Sie bitte das Fenster öffnen?', "Pouvez-vous ouvrir la fenêtre, s'il vous plaît ?"),
   ('schließen', 'fermer', 'Der Supermarkt schließt um zwanzig Uhr.', 'Le supermarché ferme à vingt heures.'),
   ('aufmachen', 'ouvrir (courant)', 'Mach bitte die Tür auf!', "Ouvre la porte, s'il te plaît !"),
   ('zumachen', 'fermer (courant)', 'Mach das Fenster zu, es ist kalt.', 'Ferme la fenêtre, il fait froid.'),
   ('kühlen', 'refroidir, garder au frais', 'Wir kühlen die Getränke im Kühlschrank.', 'Nous gardons les boissons au frais dans le réfrigérateur.'),
   ('wärmen', 'réchauffer', 'Ich wärme die Suppe in der Mikrowelle.', 'Je réchauffe la soupe au micro-ondes.'),
   ('grillen', 'faire griller', 'Im Sommer grillen wir im Garten.', 'En été, nous faisons des grillades dans le jardin.'),
   ('naschen', 'grignoter (des sucreries)', 'Die Kinder naschen gern Bonbons.', 'Les enfants aiment grignoter des bonbons.')]),
 ('La maison et le ménage',
  [('wohnen', 'habiter', 'Ich wohne in einer kleinen Wohnung.', "J'habite dans un petit appartement."),
   ('leben', 'vivre', 'Meine Eltern leben in Kamerun.', 'Mes parents vivent au Cameroun.'),
   ('mieten', 'louer (prendre en location)', 'Wir mieten eine Wohnung im Zentrum.', 'Nous louons un appartement dans le centre.'),
   ('vermieten', 'louer (donner en location)', 'Er vermietet ein Zimmer an Studenten.', 'Il loue une chambre à des étudiants.'),
   ('einziehen', 'emménager', 'Nächsten Monat ziehen wir in das neue Haus ein.', 'Le mois prochain, nous emménageons dans la nouvelle maison.'),
   ('umziehen', 'déménager', 'Meine Schwester zieht nach Berlin um.', 'Ma sœur déménage à Berlin.'),
   ('aufräumen', 'ranger', 'Räum bitte dein Zimmer auf!', "Range ta chambre, s'il te plaît !"),
   ('staubsaugen', "passer l'aspirateur", 'Ich staubsauge jeden Samstag.', "Je passe l'aspirateur tous les samedis."),
   ('wischen', 'essuyer, passer la serpillière', 'Sie wischt den Boden in der Küche.', 'Elle passe la serpillière dans la cuisine.'),
   ('fegen', 'balayer', 'Ich fege den Hof vor dem Haus.', 'Je balaie la cour devant la maison.'),
   ('bügeln', 'repasser', 'Ich bügle mein Hemd für morgen.', 'Je repasse ma chemise pour demain.'),
   ('aufhängen', 'accrocher, étendre', 'Ich hänge die Wäsche im Garten auf.', "J'étends le linge dans le jardin."),
   ('reparieren', 'réparer', 'Der Techniker repariert die Waschmaschine.', 'Le technicien répare la machine à laver.'),
   ('bauen', 'construire', 'Mein Onkel baut ein Haus im Dorf.', 'Mon oncle construit une maison au village.'),
   ('renovieren', 'rénover', 'Wir renovieren das Badezimmer.', 'Nous rénovons la salle de bains.'),
   ('streichen', 'peindre (un mur)', 'Am Wochenende streichen wir die Wände.', 'Ce week-end, nous peignons les murs.'),
   ('einrichten', 'aménager', 'Sie richtet ihr neues Zimmer ein.', 'Elle aménage sa nouvelle chambre.'),
   ('stellen', 'poser (debout)', 'Stell die Flasche bitte auf den Tisch.', "Pose la bouteille sur la table, s'il te plaît."),
   ('legen', 'poser (à plat)', 'Ich lege das Buch auf das Bett.', 'Je pose le livre sur le lit.'),
   ('hängen', 'accrocher, être accroché', 'Das Bild hängt an der Wand.', 'Le tableau est accroché au mur.'),
   ('klingeln', 'sonner', 'Jemand klingelt an der Tür.', "Quelqu'un sonne à la porte."),
   ('klopfen', 'frapper (à la porte)', 'Bitte klopfen Sie vor dem Eintreten.', "Veuillez frapper avant d'entrer."),
   ('abschließen', 'fermer à clé', 'Vergiss nicht, die Tür abzuschließen.', "N'oublie pas de fermer la porte à clé."),
   ('einschalten', 'allumer (un appareil)', 'Schalte bitte den Fernseher ein.', "Allume la télévision, s'il te plaît."),
   ('ausschalten', 'éteindre (un appareil)', 'Ich schalte den Computer am Abend aus.', "J'éteins l'ordinateur le soir."),
   ('anmachen', 'allumer (courant)', 'Mach bitte das Licht an.', "Allume la lumière, s'il te plaît."),
   ('ausmachen', 'éteindre (courant)', 'Mach den Herd aus, das Essen ist fertig.', 'Éteins la cuisinière, le repas est prêt.'),
   ('heizen', 'chauffer', 'Im Winter heizen wir das ganze Haus.', 'En hiver, nous chauffons toute la maison.'),
   ('lüften', 'aérer', 'Ich lüfte jeden Morgen das Schlafzimmer.', "J'aère la chambre chaque matin."),
   ('wegwerfen', 'jeter', 'Wirf die alten Zeitungen bitte weg.', "Jette les vieux journaux, s'il te plaît.")]),
 ('Se déplacer et voyager',
  [('fahren', 'aller (en véhicule), conduire', 'Ich fahre mit dem Bus zur Arbeit.', 'Je vais au travail en bus.'),
   ('laufen', 'courir, marcher', 'Wir laufen jeden Morgen im Park.', 'Nous courons chaque matin dans le parc.'),
   ('rennen', 'courir vite', 'Die Kinder rennen über den Schulhof.', "Les enfants courent dans la cour de l'école."),
   ('fliegen', "voler, prendre l'avion", 'Morgen fliege ich nach Frankfurt.', "Demain, je prends l'avion pour Francfort."),
   ('reisen', 'voyager', 'Wir reisen gern mit dem Zug.', 'Nous aimons voyager en train.'),
   ('ankommen', 'arriver', 'Der Zug kommt um zehn Uhr an.', 'Le train arrive à dix heures.'),
   ('abfahren', 'partir (véhicule)', 'Der Bus fährt in fünf Minuten ab.', 'Le bus part dans cinq minutes.'),
   ('abfliegen', 'décoller', 'Das Flugzeug fliegt pünktlich ab.', "L'avion décolle à l'heure."),
   ('landen', 'atterrir', 'Wir landen um sechzehn Uhr in Douala.', 'Nous atterrissons à seize heures à Douala.'),
   ('einsteigen', 'monter (dans un véhicule)', 'Bitte steigen Sie schnell ein!', "Montez vite, s'il vous plaît !"),
   ('aussteigen', "descendre (d'un véhicule)", 'Ich steige an der nächsten Haltestelle aus.', 'Je descends au prochain arrêt.'),
   ('umsteigen', 'changer (de train, de bus)', 'In Köln müssen Sie umsteigen.', 'Vous devez changer à Cologne.'),
   ('abholen', 'aller chercher', 'Ich hole dich am Flughafen ab.', "Je viens te chercher à l'aéroport."),
   ('mitnehmen', 'emmener, emporter', 'Nimm einen Regenschirm mit!', 'Emporte un parapluie !'),
   ('zurückkommen', 'revenir', 'Wann kommst du aus dem Urlaub zurück?', 'Quand reviens-tu de vacances ?'),
   ('weggehen', "s'en aller", 'Er geht ohne ein Wort weg.', "Il s'en va sans un mot."),
   ('verlassen', 'quitter', 'Ich verlasse das Büro um siebzehn Uhr.', 'Je quitte le bureau à dix-sept heures.'),
   ('überqueren', 'traverser', 'Wir überqueren die Straße an der Ampel.', 'Nous traversons la rue au feu.'),
   ('abbiegen', 'tourner', 'Biegen Sie an der Kreuzung links ab.', 'Tournez à gauche au carrefour.'),
   ('parken', 'se garer', 'Hier darf man nicht parken.', "On n'a pas le droit de se garer ici."),
   ('tanken', 'faire le plein', 'Ich muss noch schnell tanken.', 'Je dois encore vite faire le plein.'),
   ('bremsen', 'freiner', 'Der Fahrer bremst vor der Schule.', "Le chauffeur freine devant l'école."),
   ('überholen', 'doubler, dépasser', 'Das Motorrad überholt den Lastwagen.', 'La moto double le camion.'),
   ('buchen', 'réserver (voyage)', 'Ich buche ein Hotel für drei Nächte.', 'Je réserve un hôtel pour trois nuits.'),
   ('reservieren', 'réserver (table, place)', 'Ich möchte einen Tisch für zwei Personen reservieren.', 'Je voudrais réserver une table pour deux personnes.'),
   ('packen', 'faire (sa valise)', 'Heute Abend packe ich meinen Koffer.', 'Ce soir, je fais ma valise.'),
   ('besichtigen', 'visiter (un lieu)', 'Wir besichtigen morgen das Schloss.', 'Demain, nous visitons le château.'),
   ('übernachten', 'passer la nuit', 'Wir übernachten bei Freunden.', 'Nous passons la nuit chez des amis.'),
   ('sich verlaufen', 'se perdre (à pied)', 'Ich habe mich in der Stadt verlaufen.', 'Je me suis perdu dans la ville.'),
   ('wandern', 'faire de la randonnée', 'Am Sonntag wandern wir in den Bergen.', 'Dimanche, nous faisons une randonnée en montagne.')]),
 ("Les courses et l'argent",
  [('kaufen', 'acheter', 'Ich kaufe Brot beim Bäcker.', "J'achète du pain chez le boulanger."),
   ('verkaufen', 'vendre', 'Meine Tante verkauft Obst auf dem Markt.', 'Ma tante vend des fruits au marché.'),
   ('einkaufen', 'faire les courses', 'Samstags kaufen wir im Supermarkt ein.', 'Le samedi, nous faisons les courses au supermarché.'),
   ('bezahlen', 'payer', 'Kann ich mit Karte bezahlen?', 'Puis-je payer par carte ?'),
   ('zahlen', 'payer, régler', 'Wir möchten bitte zahlen.', "Nous voudrions payer, s'il vous plaît."),
   ('kosten', 'coûter', 'Was kostet ein Kilo Tomaten?', 'Combien coûte un kilo de tomates ?'),
   ('sparen', 'économiser', 'Ich spare für ein neues Handy.', "J'économise pour un nouveau téléphone."),
   ('ausgeben', 'dépenser', 'Er gibt zu viel Geld für Kleidung aus.', "Il dépense trop d'argent en vêtements."),
   ('verdienen', "gagner (de l'argent)", 'Sie verdient gut in ihrem Beruf.', 'Elle gagne bien sa vie dans son métier.'),
   ('leihen', 'prêter, emprunter', 'Kannst du mir zehn Euro leihen?', 'Peux-tu me prêter dix euros ?'),
   ('schulden', "devoir (de l'argent)", 'Ich schulde dir noch fünf Euro.', 'Je te dois encore cinq euros.'),
   ('wechseln', 'changer, échanger', 'Können Sie mir fünfzig Euro wechseln?', 'Pouvez-vous me faire la monnaie de cinquante euros ?'),
   ('abheben', "retirer (de l'argent)", 'Ich hebe Geld am Automaten ab.', "Je retire de l'argent au distributeur."),
   ('überweisen', "virer (de l'argent)", 'Ich überweise die Miete jeden Monat.', 'Je vire le loyer chaque mois.'),
   ('umtauschen', 'échanger (un article)', 'Ich möchte diese Hose umtauschen.', 'Je voudrais échanger ce pantalon.'),
   ('zurückgeben', 'rendre', 'Gib mir bitte mein Buch zurück.', "Rends-moi mon livre, s'il te plaît."),
   ('anprobieren', 'essayer (un vêtement)', 'Kann ich die Jacke anprobieren?', 'Puis-je essayer la veste ?'),
   ('passen', 'aller (taille), convenir', 'Die Schuhe passen mir nicht.', 'Les chaussures ne me vont pas.'),
   ('wiegen', 'peser', 'Die Verkäuferin wiegt die Bananen.', 'La vendeuse pèse les bananes.'),
   ('einpacken', 'emballer', 'Können Sie das Geschenk einpacken?', 'Pouvez-vous emballer le cadeau ?'),
   ('auspacken', 'déballer', 'Die Kinder packen ihre Geschenke aus.', 'Les enfants déballent leurs cadeaux.'),
   ('liefern', 'livrer', 'Die Firma liefert die Möbel am Montag.', "L'entreprise livre les meubles lundi."),
   ('handeln', 'marchander, agir', 'Auf dem Markt kann man handeln.', 'Au marché, on peut marchander.'),
   ('vergleichen', 'comparer', 'Ich vergleiche immer die Preise.', 'Je compare toujours les prix.'),
   ('auswählen', 'choisir, sélectionner', 'Wähl dir ein Eis aus!', 'Choisis-toi une glace !'),
   ('anbieten', 'proposer, offrir', 'Der Laden bietet heute Rabatte an.', "Le magasin propose des réductions aujourd'hui."),
   ('schenken', 'offrir (un cadeau)', 'Ich schenke meiner Mutter Blumen.', "J'offre des fleurs à ma mère."),
   ('suchen', 'chercher', 'Ich suche eine Apotheke in der Nähe.', 'Je cherche une pharmacie à proximité.'),
   ('holen', 'aller chercher (une chose)', 'Ich hole schnell Milch aus dem Laden.', 'Je vais vite chercher du lait au magasin.'),
   ('tragen', 'porter', 'Er trägt die schweren Taschen nach Hause.', 'Il porte les sacs lourds à la maison.')]),
 ('Le travail',
  [('arbeiten', 'travailler', 'Ich arbeite in einem Krankenhaus.', 'Je travaille dans un hôpital.'),
   ('verdanken', "devoir (quelque chose à quelqu'un)", 'Diese Stelle verdanke ich meinem Onkel.', 'Je dois ce poste à mon oncle.'),
   ('sich bewerben', 'postuler', 'Ich bewerbe mich um eine neue Stelle.', 'Je postule à un nouveau poste.'),
   ('einstellen', 'embaucher, régler', 'Die Firma stellt zehn neue Mitarbeiter ein.', "L'entreprise embauche dix nouveaux employés."),
   ('kündigen', 'démissionner, licencier', 'Er kündigt seinen Job im Dezember.', 'Il démissionne de son travail en décembre.'),
   ('leiten', 'diriger', 'Frau Weber leitet unsere Abteilung.', 'Madame Weber dirige notre service.'),
   ('planen', 'planifier', 'Wir planen ein Treffen für nächste Woche.', 'Nous planifions une réunion pour la semaine prochaine.'),
   ('organisieren', 'organiser', 'Sie organisiert die Feier im Büro.', 'Elle organise la fête au bureau.'),
   ('vorbereiten', 'préparer', 'Ich bereite die Präsentation vor.', 'Je prépare la présentation.'),
   ('erledigen', 'régler, accomplir', 'Ich muss heute viele Aufgaben erledigen.', "Je dois accomplir beaucoup de tâches aujourd'hui."),
   ('schaffen', 'réussir à faire', 'Schaffst du das bis morgen?', "Arrives-tu à faire ça d'ici demain ?"),
   ('schicken', 'envoyer', 'Ich schicke dir die Datei per E-Mail.', "Je t'envoie le fichier par e-mail."),
   ('senden', 'envoyer, transmettre', 'Bitte senden Sie uns Ihre Unterlagen.', 'Veuillez nous envoyer vos documents.'),
   ('unterschreiben', 'signer', 'Unterschreiben Sie bitte hier unten.', "Signez ici en bas, s'il vous plaît."),
   ('ausfüllen', 'remplir (un formulaire)', 'Sie müssen dieses Formular ausfüllen.', 'Vous devez remplir ce formulaire.'),
   ('kopieren', 'copier, photocopier', 'Kannst du die Seite für mich kopieren?', 'Peux-tu photocopier la page pour moi ?'),
   ('drucken', 'imprimer', 'Ich drucke den Vertrag zweimal.', "J'imprime le contrat en deux exemplaires."),
   ('speichern', 'enregistrer (un fichier)', 'Speichere das Dokument, bevor du gehst.', 'Enregistre le document avant de partir.'),
   ('löschen', 'supprimer, éteindre (un feu)', 'Ich lösche die alten E-Mails.', 'Je supprime les anciens e-mails.'),
   ('tippen', 'taper (au clavier)', 'Sie tippt sehr schnell am Computer.', "Elle tape très vite à l'ordinateur."),
   ('telefonieren', 'téléphoner', 'Der Chef telefoniert gerade mit einem Kunden.', 'Le chef est au téléphone avec un client.'),
   ('besprechen', 'discuter de', 'Wir besprechen das Projekt am Montag.', 'Nous discutons du projet lundi.'),
   ('vereinbaren', 'convenir de', 'Ich möchte einen Termin vereinbaren.', 'Je voudrais prendre un rendez-vous.'),
   ('absagen', 'annuler (un rendez-vous)', 'Ich muss den Termin leider absagen.', 'Je dois malheureusement annuler le rendez-vous.'),
   ('verschieben', 'reporter', 'Können wir das Treffen auf Freitag verschieben?', 'Pouvons-nous reporter la réunion à vendredi ?'),
   ('teilnehmen', 'participer', 'Ich nehme an einem Deutschkurs teil.', "Je participe à un cours d'allemand."),
   ('vertreten', 'remplacer, représenter', 'Heute vertrete ich meine Kollegin.', "Aujourd'hui, je remplace ma collègue."),
   ('beraten', 'conseiller', 'Die Verkäuferin berät die Kunden gut.', 'La vendeuse conseille bien les clients.'),
   ('bedienen', 'servir (un client)', 'Der Kellner bedient die Gäste freundlich.', 'Le serveur sert les clients aimablement.'),
   ('entwickeln', 'développer', 'Mein Freund entwickelt Apps für Handys.', 'Mon ami développe des applications pour téléphones.')]),
 ('Apprendre et penser',
  [('lernen', 'apprendre', 'Ich lerne seit drei Monaten Deutsch.', "J'apprends l'allemand depuis trois mois."),
   ('lehren', 'enseigner', 'Er lehrt Mathematik an der Universität.', "Il enseigne les mathématiques à l'université."),
   ('unterrichten', 'donner des cours', 'Frau Klein unterrichtet Deutsch.', "Madame Klein donne des cours d'allemand."),
   ('studieren', 'faire des études', 'Meine Tochter studiert Medizin.', 'Ma fille fait des études de médecine.'),
   ('üben', "s'exercer", 'Wir üben jeden Tag die Aussprache.', 'Nous nous exerçons chaque jour à la prononciation.'),
   ('sich konzentrieren', 'se concentrer', 'Bei dem Lärm kann ich mich nicht konzentrieren.', "Avec ce bruit, je n'arrive pas à me concentrer."),
   ('bestehen', 'réussir (un examen)', 'Ich will die A1-Prüfung bestehen.', "Je veux réussir l'examen A1."),
   ('durchfallen', 'échouer (à un examen)', 'Er ist leider in der Prüfung durchgefallen.', "Il a malheureusement échoué à l'examen."),
   ('rechnen', 'calculer', 'Die Schüler rechnen ohne Taschenrechner.', 'Les élèves calculent sans calculatrice.'),
   ('zählen', 'compter', 'Das Kind zählt schon bis zwanzig.', "L'enfant compte déjà jusqu'à vingt."),
   ('zeichnen', 'dessiner', 'Meine Tochter zeichnet gern Tiere.', 'Ma fille aime dessiner des animaux.'),
   ('malen', 'peindre', 'Die Kinder malen ein Bild für Oma.', 'Les enfants peignent un dessin pour mamie.'),
   ('notieren', 'noter', 'Ich notiere mir die neue Adresse.', 'Je note la nouvelle adresse.'),
   ('markieren', 'surligner, marquer', 'Markieren Sie die wichtigen Wörter.', 'Surlignez les mots importants.'),
   ('korrigieren', 'corriger', 'Die Lehrerin korrigiert unsere Hausaufgaben.', 'La professeure corrige nos devoirs.'),
   ('verbessern', 'améliorer', 'Ich möchte mein Deutsch verbessern.', 'Je voudrais améliorer mon allemand.'),
   ('vergessen', 'oublier', 'Ich vergesse oft meinen Regenschirm.', "J'oublie souvent mon parapluie."),
   ('sich erinnern', 'se souvenir', 'Erinnerst du dich an unseren Lehrer?', 'Te souviens-tu de notre professeur ?'),
   ('sich merken', 'retenir, mémoriser', 'Ich kann mir Zahlen nicht gut merken.', 'Je ne retiens pas bien les chiffres.'),
   ('kennen', 'connaître', 'Kennst du meinen Nachbarn?', 'Connais-tu mon voisin ?'),
   ('kennenlernen', 'faire la connaissance de', 'Ich möchte deine Familie kennenlernen.', 'Je voudrais faire la connaissance de ta famille.'),
   ('bedeuten', 'signifier', 'Was bedeutet dieses Wort?', 'Que signifie ce mot ?'),
   ('aussprechen', 'prononcer', 'Wie spricht man dieses Wort aus?', 'Comment prononce-t-on ce mot ?'),
   ('nachdenken', 'réfléchir', 'Ich muss über das Angebot nachdenken.', "Je dois réfléchir à l'offre."),
   ('überlegen', 'réfléchir, considérer', 'Ich überlege, ob ich mitkomme.', 'Je me demande si je viens avec vous.'),
   ('entscheiden', 'décider', 'Du musst dich heute entscheiden.', "Tu dois te décider aujourd'hui."),
   ('raten', 'deviner, conseiller', 'Rate mal, wen ich getroffen habe!', "Devine qui j'ai rencontré !"),
   ('prüfen', 'vérifier, examiner', 'Bitte prüfen Sie Ihre Angaben.', 'Veuillez vérifier vos informations.'),
   ('lösen', 'résoudre', 'Kannst du diese Aufgabe lösen?', 'Peux-tu résoudre cet exercice ?'),
   ('aufpassen', 'faire attention', 'Pass auf, die Straße ist glatt!', 'Fais attention, la route est glissante !')]),
 ('Sentiments et relations',
  [('lieben', "aimer (d'amour)", 'Ich liebe meine Familie über alles.', "J'aime ma famille plus que tout."),
   ('hassen', 'détester', 'Ich hasse es, im Stau zu stehen.', 'Je déteste être dans les embouteillages.'),
   ('gefallen', 'plaire', 'Dein neues Kleid gefällt mir sehr.', 'Ta nouvelle robe me plaît beaucoup.'),
   ('sich freuen', 'se réjouir', 'Ich freue mich auf das Wochenende.', 'Je me réjouis du week-end.'),
   ('lachen', 'rire', 'Wir lachen viel zusammen.', 'Nous rions beaucoup ensemble.'),
   ('lächeln', 'sourire', 'Die Verkäuferin lächelt immer freundlich.', 'La vendeuse sourit toujours aimablement.'),
   ('weinen', 'pleurer', 'Das Kind weint, weil es Hunger hat.', "L'enfant pleure parce qu'il a faim."),
   ('sich ärgern', "se fâcher, s'énerver", 'Ich ärgere mich über den Stau.', "Je m'énerve à cause des embouteillages."),
   ('sich aufregen', "s'énerver", 'Reg dich nicht so auf!', "Ne t'énerve pas comme ça !"),
   ('sich beruhigen', 'se calmer', 'Beruhige dich, alles wird gut.', 'Calme-toi, tout ira bien.'),
   ('sich fürchten', 'avoir peur', 'Mein Sohn fürchtet sich vor Hunden.', 'Mon fils a peur des chiens.'),
   ('hoffen', 'espérer', 'Ich hoffe, du kommst bald wieder.', "J'espère que tu reviendras bientôt."),
   ('wünschen', 'souhaiter', 'Ich wünsche dir einen schönen Tag.', 'Je te souhaite une bonne journée.'),
   ('fühlen', 'ressentir, se sentir', 'Ich fühle mich heute viel besser.', "Je me sens beaucoup mieux aujourd'hui."),
   ('vermissen', "manquer (regretter l'absence)", 'Ich vermisse meine Heimat sehr.', 'Mon pays me manque beaucoup.'),
   ('vertrauen', 'faire confiance', 'Ich vertraue meinem besten Freund.', 'Je fais confiance à mon meilleur ami.'),
   ('sich verlieben', 'tomber amoureux', 'Er hat sich in seine Nachbarin verliebt.', 'Il est tombé amoureux de sa voisine.'),
   ('heiraten', 'se marier', 'Meine Cousine heiratet im August.', 'Ma cousine se marie en août.'),
   ('sich trennen', 'se séparer', 'Meine Nachbarn haben sich getrennt.', 'Mes voisins se sont séparés.'),
   ('küssen', 'embrasser', 'Die Mutter küsst ihr Baby.', 'La mère embrasse son bébé.'),
   ('umarmen', 'prendre dans ses bras', 'Zum Abschied umarmen wir uns.', 'Pour nous dire au revoir, nous nous prenons dans les bras.'),
   ('treffen', 'rencontrer', 'Ich treffe meine Freunde im Café.', 'Je retrouve mes amis au café.'),
   ('besuchen', 'rendre visite, visiter', 'Am Sonntag besuchen wir die Großeltern.', 'Dimanche, nous rendons visite aux grands-parents.'),
   ('helfen', 'aider', 'Kannst du mir beim Umzug helfen?', "Peux-tu m'aider pour le déménagement ?"),
   ('sich kümmern', "s'occuper de", 'Sie kümmert sich um ihre kranke Mutter.', "Elle s'occupe de sa mère malade."),
   ('stören', 'déranger', 'Entschuldigung, störe ich Sie?', 'Excusez-moi, est-ce que je vous dérange ?'),
   ('gratulieren', 'féliciter', 'Ich gratuliere dir zum Geburtstag!', 'Je te félicite pour ton anniversaire !'),
   ('feiern', 'fêter', 'Wir feiern Silvester mit Freunden.', 'Nous fêtons le Nouvel An avec des amis.'),
   ('verzeihen', 'pardonner', 'Kannst du mir verzeihen?', 'Peux-tu me pardonner ?'),
   ('sich verabschieden', 'dire au revoir', 'Ich verabschiede mich jetzt, bis morgen!', 'Je vous dis au revoir maintenant, à demain !')]),
 ('La santé et le corps',
  [('wehtun', 'faire mal', 'Mein Kopf tut seit heute Morgen weh.', "J'ai mal à la tête depuis ce matin."),
   ('sich erkälten', "s'enrhumer", 'Zieh eine Jacke an, sonst erkältest du dich.', "Mets une veste, sinon tu vas t'enrhumer."),
   ('husten', 'tousser', 'Das Kind hustet die ganze Nacht.', "L'enfant tousse toute la nuit."),
   ('niesen', 'éternuer', 'Im Frühling muss ich oft niesen.', "Au printemps, j'éternue souvent."),
   ('bluten', 'saigner', 'Dein Finger blutet ja!', 'Mais ton doigt saigne !'),
   ('sich verletzen', 'se blesser', 'Er hat sich beim Fußball verletzt.', "Il s'est blessé au football."),
   ('brechen', 'casser, se fracturer', 'Sie hat sich den Arm gebrochen.', "Elle s'est cassé le bras."),
   ('untersuchen', 'examiner', 'Die Ärztin untersucht den Patienten.', 'La docteure examine le patient.'),
   ('verschreiben', 'prescrire', 'Der Arzt verschreibt mir Tabletten.', 'Le médecin me prescrit des comprimés.'),
   ('einnehmen', 'prendre (un médicament)', 'Nehmen Sie die Tablette nach dem Essen ein.', 'Prenez le comprimé après le repas.'),
   ('impfen', 'vacciner', 'Der Arzt impft das Baby heute.', "Le médecin vaccine le bébé aujourd'hui."),
   ('operieren', 'opérer', 'Morgen wird mein Vater am Knie operiert.', 'Demain, mon père se fait opérer du genou.'),
   ('heilen', 'guérir', 'Die Wunde heilt langsam.', 'La plaie guérit lentement.'),
   ('sich erholen', 'se rétablir, se reposer', 'Im Urlaub erhole ich mich gut.', 'En vacances, je me repose bien.'),
   ('atmen', 'respirer', 'Atmen Sie bitte tief ein und aus.', "Inspirez et expirez profondément, s'il vous plaît."),
   ('schwitzen', 'transpirer', 'Beim Sport schwitze ich sehr.', 'Je transpire beaucoup en faisant du sport.'),
   ('frieren', 'avoir froid, geler', 'Ich friere, mach bitte die Heizung an.', "J'ai froid, allume le chauffage, s'il te plaît."),
   ('zittern', 'trembler', 'Er zittert vor Kälte.', 'Il tremble de froid.'),
   ('abnehmen', 'maigrir, décrocher', 'Ich möchte fünf Kilo abnehmen.', 'Je voudrais perdre cinq kilos.'),
   ('zunehmen', 'grossir, augmenter', 'Im Winter nehme ich immer zu.', 'En hiver, je grossis toujours.'),
   ('rauchen', 'fumer', 'Hier darf man nicht rauchen.', 'Il est interdit de fumer ici.'),
   ('sterben', 'mourir', 'Sein Großvater ist letztes Jahr gestorben.', "Son grand-père est mort l'année dernière."),
   ('geboren werden', 'naître', 'Meine Tochter wurde im Mai geboren.', 'Ma fille est née en mai.'),
   ('wachsen', 'grandir, pousser', 'Die Kinder wachsen so schnell.', 'Les enfants grandissent si vite.'),
   ('pflegen', 'soigner, prendre soin de', 'Sie pflegt ihren kranken Vater.', 'Elle soigne son père malade.'),
   ('schützen', 'protéger', 'Die Creme schützt die Haut vor der Sonne.', 'La crème protège la peau du soleil.'),
   ('riechen', 'sentir (odeur)', 'Hier riecht es nach frischem Brot.', 'Ça sent le pain frais ici.'),
   ('berühren', 'toucher', 'Bitte die Ware nicht berühren.', 'Prière de ne pas toucher la marchandise.'),
   ('kauen', 'mâcher', 'Du musst das Fleisch gut kauen.', 'Tu dois bien mâcher la viande.'),
   ('schlucken', 'avaler', 'Ich kann die Tablette nicht schlucken.', "Je n'arrive pas à avaler le comprimé.")]),
 ('Loisirs, sport et médias',
  [('spielen', 'jouer', 'Die Kinder spielen im Hof Fußball.', 'Les enfants jouent au football dans la cour.'),
   ('singen', 'chanter', 'Sie singt im Chor der Kirche.', "Elle chante dans la chorale de l'église."),
   ('tanzen', 'danser', 'Auf der Hochzeit tanzen alle Gäste.', 'Au mariage, tous les invités dansent.'),
   ('schwimmen', 'nager', 'Im Sommer schwimmen wir im See.', 'En été, nous nageons dans le lac.'),
   ('trainieren', "s'entraîner", 'Er trainiert dreimal pro Woche.', "Il s'entraîne trois fois par semaine."),
   ('gewinnen', 'gagner', 'Unsere Mannschaft gewinnt heute bestimmt.', "Notre équipe gagne sûrement aujourd'hui."),
   ('verlieren', 'perdre', 'Ich verliere immer beim Kartenspielen.', 'Je perds toujours aux cartes.'),
   ('werfen', 'lancer', 'Wirf mir bitte den Ball zu!', "Lance-moi le ballon, s'il te plaît !"),
   ('fangen', 'attraper', 'Der Torwart fängt den Ball.', 'Le gardien attrape le ballon.'),
   ('springen', 'sauter', 'Die Kinder springen ins Wasser.', "Les enfants sautent dans l'eau."),
   ('klettern', 'grimper', 'Die Katze klettert auf den Baum.', "Le chat grimpe à l'arbre."),
   ('reiten', 'monter à cheval', 'Meine Nichte reitet jeden Samstag.', 'Ma nièce monte à cheval tous les samedis.'),
   ('angeln', 'pêcher à la ligne', 'Mein Opa angelt gern am Fluss.', 'Mon grand-père aime pêcher au bord du fleuve.'),
   ('fernsehen', 'regarder la télévision', 'Abends sehen wir zusammen fern.', 'Le soir, nous regardons la télévision ensemble.'),
   ('schauen', 'regarder', 'Schau mal, da kommt der Bus!', 'Regarde, voilà le bus qui arrive !'),
   ('gucken', 'regarder (familier)', 'Wir gucken heute Abend einen Film.', 'Nous regardons un film ce soir.'),
   ('fotografieren', 'photographier', 'Sie fotografiert gern Blumen.', 'Elle aime photographier les fleurs.'),
   ('filmen', 'filmer', 'Er filmt das Konzert mit dem Handy.', 'Il filme le concert avec son téléphone.'),
   ('chatten', 'discuter en ligne', 'Ich chatte jeden Abend mit meiner Schwester.', 'Je discute en ligne chaque soir avec ma sœur.'),
   ('surfen', 'naviguer (sur Internet)', 'Die Jugendlichen surfen viel im Internet.', 'Les jeunes naviguent beaucoup sur Internet.'),
   ('herunterladen', 'télécharger', 'Ich lade die App auf mein Handy herunter.', "Je télécharge l'application sur mon téléphone."),
   ('hochladen', 'mettre en ligne', 'Sie lädt die Fotos ins Internet hoch.', 'Elle met les photos en ligne.'),
   ('posten', 'publier (en ligne)', 'Er postet jeden Tag ein Video.', 'Il publie une vidéo chaque jour.'),
   ('teilen', 'partager', 'Wir teilen die Pizza durch vier.', 'Nous partageons la pizza en quatre.'),
   ('basteln', 'bricoler (travaux manuels)', 'Die Kinder basteln Sterne aus Papier.', 'Les enfants fabriquent des étoiles en papier.'),
   ('stricken', 'tricoter', 'Meine Oma strickt mir einen Schal.', 'Ma grand-mère me tricote une écharpe.'),
   ('nähen', 'coudre', 'Die Schneiderin näht ein Kleid.', 'La couturière coud une robe.'),
   ('spazieren gehen', 'se promener', 'Nach dem Essen gehen wir spazieren.', 'Après le repas, nous allons nous promener.'),
   ('ausgehen', 'sortir (le soir)', 'Am Freitag gehen wir mit Freunden aus.', 'Vendredi, nous sortons avec des amis.'),
   ('sich unterhalten', "bavarder, s'entretenir", 'Wir unterhalten uns über den Film.', 'Nous parlons du film.')]),
 ('Météo, nature et animaux',
  [('regnen', 'pleuvoir', 'Es regnet schon den ganzen Tag.', 'Il pleut déjà toute la journée.'),
   ('schneien', 'neiger', 'In den Bergen schneit es im Winter.', 'En montagne, il neige en hiver.'),
   ('scheinen', 'briller, sembler', 'Heute scheint endlich die Sonne.', "Aujourd'hui, le soleil brille enfin."),
   ('donnern', 'tonner', 'Hörst du, wie es donnert?', 'Entends-tu le tonnerre ?'),
   ('blitzen', 'faire des éclairs', 'Draußen blitzt es sehr stark.', 'Dehors, il y a de gros éclairs.'),
   ('wehen', 'souffler (vent)', 'Am Meer weht immer ein starker Wind.', 'Au bord de la mer, un vent fort souffle toujours.'),
   ('tauen', 'dégeler, fondre', 'Im Frühling taut der Schnee.', 'Au printemps, la neige fond.'),
   ('blühen', 'fleurir', 'Im Mai blühen die Rosen im Garten.', 'En mai, les roses fleurissent dans le jardin.'),
   ('pflanzen', 'planter', 'Wir pflanzen Tomaten hinter dem Haus.', 'Nous plantons des tomates derrière la maison.'),
   ('ernten', 'récolter', 'Im Herbst ernten die Bauern den Mais.', 'En automne, les paysans récoltent le maïs.'),
   ('pflücken', 'cueillir', 'Die Kinder pflücken Mangos vom Baum.', "Les enfants cueillent des mangues sur l'arbre."),
   ('säen', 'semer', 'Der Bauer sät im Frühling den Weizen.', 'Le paysan sème le blé au printemps.'),
   ('graben', 'creuser', 'Der Hund gräbt ein Loch im Garten.', 'Le chien creuse un trou dans le jardin.'),
   ('füttern', 'nourrir (un animal)', 'Ich füttere die Katze zweimal am Tag.', 'Je nourris le chat deux fois par jour.'),
   ('bellen', 'aboyer', 'Der Hund vom Nachbarn bellt die ganze Nacht.', 'Le chien du voisin aboie toute la nuit.'),
   ('beißen', 'mordre', 'Keine Angst, mein Hund beißt nicht.', "N'aie pas peur, mon chien ne mord pas."),
   ('jagen', 'chasser', 'Die Katze jagt eine Maus.', 'Le chat chasse une souris.'),
   ('fließen', 'couler', 'Der Fluss fließt durch die Stadt.', 'Le fleuve coule à travers la ville.'),
   ('brennen', 'brûler', 'Im Kamin brennt ein Feuer.', 'Un feu brûle dans la cheminée.'),
   ('leuchten', 'luire, éclairer', 'In der Nacht leuchten die Sterne.', 'La nuit, les étoiles brillent.'),
   ('aufgehen', "se lever (soleil), s'ouvrir", 'Die Sonne geht um sechs Uhr auf.', 'Le soleil se lève à six heures.'),
   ('untergehen', 'se coucher (soleil), couler', 'Am Abend geht die Sonne im Westen unter.', "Le soir, le soleil se couche à l'ouest."),
   ('schmelzen', 'fondre', 'Das Eis schmilzt in der Sonne.', 'La glace fond au soleil.'),
   ('trocknen', 'sécher', 'Die Wäsche trocknet schnell im Wind.', 'Le linge sèche vite au vent.'),
   ('stinken', 'puer', 'Der Müll stinkt, bring ihn bitte raus.', "La poubelle pue, sors-la s'il te plaît."),
   ('fallen', 'tomber', 'Im Herbst fallen die Blätter von den Bäumen.', 'En automne, les feuilles tombent des arbres.'),
   ('steigen', 'monter, augmenter', 'Die Temperaturen steigen auf dreißig Grad.', 'Les températures montent à trente degrés.'),
   ('sinken', 'baisser, couler', 'Nachts sinkt die Temperatur unter null.', 'La nuit, la température descend en dessous de zéro.'),
   ('sich verändern', 'changer, se transformer', 'Das Wetter verändert sich schnell.', 'Le temps change vite.'),
   ('verschmutzen', 'polluer, salir', 'Die Autos verschmutzen die Luft.', "Les voitures polluent l'air.")]),
 ('Actions du quotidien',
  [('benutzen', 'utiliser', 'Darf ich kurz dein Handy benutzen?', 'Puis-je utiliser ton téléphone un instant ?'),
   ('verwenden', 'employer, utiliser', 'Für den Kuchen verwende ich Butter.', "Pour le gâteau, j'utilise du beurre."),
   ('halten', "tenir, s'arrêter", 'Kannst du bitte meine Tasche halten?', "Peux-tu tenir mon sac, s'il te plaît ?"),
   ('ziehen', 'tirer', 'Bitte an der Tür ziehen, nicht drücken.', "Tirez la porte, s'il vous plaît, ne poussez pas."),
   ('drücken', 'appuyer, pousser', 'Drücken Sie den grünen Knopf.', 'Appuyez sur le bouton vert.'),
   ('schieben', 'pousser (faire rouler)', 'Er schiebt das Fahrrad den Berg hinauf.', "Il pousse le vélo jusqu'en haut de la côte."),
   ('heben', 'soulever', 'Kannst du mir helfen, den Tisch zu heben?', "Peux-tu m'aider à soulever la table ?"),
   ('drehen', 'tourner', 'Dreh den Schlüssel nach rechts.', 'Tourne la clé vers la droite.'),
   ('schütteln', 'secouer', 'Die Flasche vor dem Öffnen schütteln.', "Secouer la bouteille avant de l'ouvrir."),
   ('binden', 'attacher, nouer', 'Das Kind bindet seine Schuhe allein.', "L'enfant attache ses chaussures tout seul."),
   ('kleben', 'coller', 'Ich klebe eine Briefmarke auf den Brief.', 'Je colle un timbre sur la lettre.'),
   ('falten', 'plier', 'Sie faltet die Handtücher ordentlich.', 'Elle plie soigneusement les serviettes.'),
   ('wickeln', 'enrouler, langer', 'Der Vater wickelt das Baby.', 'Le père change la couche du bébé.'),
   ('zeigen', 'montrer', 'Zeigen Sie mir bitte Ihren Ausweis.', "Montrez-moi votre pièce d'identité, s'il vous plaît."),
   ('verstecken', 'cacher', 'Die Kinder verstecken sich hinter dem Sofa.', 'Les enfants se cachent derrière le canapé.'),
   ('aufheben', 'ramasser, conserver', 'Heb bitte das Papier vom Boden auf.', "Ramasse le papier par terre, s'il te plaît."),
   ('behalten', 'garder', 'Sie können das Wechselgeld behalten.', 'Vous pouvez garder la monnaie.'),
   ('wählen', 'choisir, voter, composer', 'Wählen Sie die Nummer eins eins zwei.', 'Composez le numéro un un deux.'),
   ('erreichen', 'atteindre, joindre', 'Ich kann dich telefonisch nicht erreichen.', "Je n'arrive pas à te joindre par téléphone."),
   ('verpassen', 'rater, manquer', 'Ich habe heute Morgen den Bus verpasst.', "J'ai raté le bus ce matin."),
   ('versuchen', 'essayer', 'Versuch es bitte noch einmal.', "Essaie encore une fois, s'il te plaît."),
   ('gelingen', 'réussir (impersonnel)', 'Der Kuchen ist mir gut gelungen.', "J'ai bien réussi le gâteau."),
   ('passieren', 'se passer, arriver', 'Was ist denn hier passiert?', "Mais que s'est-il passé ici ?"),
   ('geschehen', 'se produire', 'Der Unfall geschah gestern Abend.', "L'accident s'est produit hier soir."),
   ('ändern', 'modifier, changer', 'Ich möchte mein Passwort ändern.', 'Je voudrais changer mon mot de passe.'),
   ('funktionieren', 'fonctionner', 'Der Drucker funktioniert nicht mehr.', "L'imprimante ne fonctionne plus."),
   ('kaputtgehen', 'se casser, tomber en panne', 'Mein Handy ist gestern kaputtgegangen.', 'Mon téléphone est tombé en panne hier.'),
   ('fehlen', 'manquer', 'In der Suppe fehlt noch Salz.', 'Il manque encore du sel dans la soupe.'),
   ('gehören', 'appartenir', 'Wem gehört dieser Rucksack?', 'À qui appartient ce sac à dos ?'),
   ('reichen', 'suffire, tendre', 'Danke, das reicht für heute.', "Merci, ça suffit pour aujourd'hui.")]),
 ('Administration, ville et société',
  [('anmelden', 'inscrire, déclarer', 'Ich muss mich beim Bürgeramt anmelden.', 'Je dois me déclarer à la mairie.'),
   ('abmelden', 'désinscrire', 'Ich melde mein altes Auto ab.', 'Je fais radier mon ancienne voiture.'),
   ('beantragen', 'faire une demande de', 'Ich beantrage ein Visum für Deutschland.', "Je fais une demande de visa pour l'Allemagne."),
   ('verlängern', 'prolonger', 'Ich muss meinen Pass verlängern.', 'Je dois faire prolonger mon passeport.'),
   ('abgeben', 'remettre, déposer', 'Bitte geben Sie das Formular am Schalter ab.', 'Veuillez remettre le formulaire au guichet.'),
   ('erhalten', 'recevoir (formel)', 'Sie erhalten den Brief in drei Tagen.', 'Vous recevrez la lettre dans trois jours.'),
   ('bestätigen', 'confirmer', 'Bitte bestätigen Sie den Termin per E-Mail.', 'Veuillez confirmer le rendez-vous par e-mail.'),
   ('erlauben', 'permettre', 'Meine Eltern erlauben mir, länger zu bleiben.', 'Mes parents me permettent de rester plus longtemps.'),
   ('verbieten', 'interdire', 'Der Arzt verbietet mir Zucker.', "Le médecin m'interdit le sucre."),
   ('informieren', 'informer', 'Bitte informieren Sie mich rechtzeitig.', "Veuillez m'informer à temps."),
   ('sich beschweren', 'se plaindre', 'Die Nachbarn beschweren sich über den Lärm.', 'Les voisins se plaignent du bruit.'),
   ('fordern', 'exiger', 'Die Arbeiter fordern mehr Lohn.', 'Les ouvriers exigent un meilleur salaire.'),
   ('empfehlen', 'recommander', 'Können Sie mir ein gutes Restaurant empfehlen?', 'Pouvez-vous me recommander un bon restaurant ?'),
   ('vorschlagen', 'proposer, suggérer', 'Ich schlage vor, wir gehen zu Fuß.', 'Je propose que nous y allions à pied.'),
   ('zustimmen', 'approuver', 'Ich stimme deinem Vorschlag zu.', "J'approuve ta proposition."),
   ('ablehnen', 'refuser', 'Er lehnt die Einladung höflich ab.', "Il refuse poliment l'invitation."),
   ('annehmen', 'accepter', 'Ich nehme das Angebot gern an.', "J'accepte volontiers l'offre."),
   ('melden', 'signaler, annoncer', 'Ich melde den Diebstahl bei der Polizei.', 'Je signale le vol à la police.'),
   ('stehlen', 'voler (dérober)', 'Jemand hat mein Fahrrad gestohlen.', "Quelqu'un a volé mon vélo."),
   ('kontrollieren', 'contrôler', 'Die Polizei kontrolliert die Ausweise.', "La police contrôle les papiers d'identité."),
   ('retten', 'sauver', 'Die Feuerwehr rettet die Katze vom Dach.', 'Les pompiers sauvent le chat sur le toit.'),
   ('warnen', 'avertir', 'Ich warne dich: Der Hund ist gefährlich.', "Je t'avertis : le chien est dangereux."),
   ('folgen', 'suivre', 'Bitte folgen Sie mir zum Ausgang.', 'Veuillez me suivre vers la sortie.'),
   ('führen', 'guider, mener', 'Diese Straße führt direkt zum Bahnhof.', 'Cette rue mène directement à la gare.'),
   ('begleiten', 'accompagner', 'Ich begleite meine Mutter zum Arzt.', "J'accompagne ma mère chez le médecin."),
   ('einwerfen', 'poster, insérer', 'Wirf den Brief bitte in den Briefkasten ein.', "Mets la lettre dans la boîte aux lettres, s'il te plaît."),
   ('abstimmen', 'voter', 'Wir stimmen über den Vorschlag ab.', 'Nous votons sur la proposition.'),
   ('spenden', 'faire un don', 'Wir spenden Kleidung für arme Familien.', 'Nous donnons des vêtements pour les familles pauvres.'),
   ('gründen', 'fonder', 'Mein Freund gründet eine eigene Firma.', 'Mon ami fonde sa propre entreprise.'),
   ('gelten', 'être valable', 'Das Ticket gilt nur heute.', "Le ticket n'est valable qu'aujourd'hui.")])]
GUIDE_TRENNBAR = [('auf+stehen', 'se lever', 'Ich stehe um halb sieben auf.', 'Je me lève à six heures et demie.'),
 ('auf+wachen', 'se réveiller', 'Das Baby wacht nachts oft auf.', 'Le bébé se réveille souvent la nuit.'),
 ('auf+machen', 'ouvrir', 'Der Laden macht um neun Uhr auf.', 'Le magasin ouvre à neuf heures.'),
 ('auf+räumen', 'ranger', 'Am Samstag räume ich die Küche auf.', 'Samedi, je range la cuisine.'),
 ('auf+hören', 'arrêter', 'Der Regen hört endlich auf.', "La pluie s'arrête enfin."),
 ('auf+passen', 'faire attention', 'Die Oma passt auf die Kinder auf.', 'La grand-mère surveille les enfants.'),
 ('auf+schreiben', 'noter', 'Ich schreibe mir die Telefonnummer auf.', 'Je note le numéro de téléphone.'),
 ('auf+hängen', 'accrocher', 'Er hängt seine Jacke im Flur auf.', 'Il accroche sa veste dans le couloir.'),
 ('an+rufen', 'téléphoner', 'Meine Mutter ruft mich jeden Sonntag an.', "Ma mère m'appelle tous les dimanches."),
 ('an+fangen', 'commencer', 'Die Arbeit fängt um acht Uhr an.', 'Le travail commence à huit heures.'),
 ('an+kommen', 'arriver', 'Wir kommen gegen Mittag in Hamburg an.', 'Nous arrivons vers midi à Hambourg.'),
 ('an+ziehen', 'mettre (un vêtement)', 'Heute ziehe ich meinen warmen Mantel an.', "Aujourd'hui, je mets mon manteau chaud."),
 ('an+machen', 'allumer', 'Sie macht das Radio in der Küche an.', 'Elle allume la radio dans la cuisine.'),
 ('an+sehen', 'regarder', 'Sieh dir dieses Foto an!', 'Regarde cette photo !'),
 ('an+bieten', 'proposer', 'Ich biete meinem Gast einen Tee an.', 'Je propose un thé à mon invité.'),
 ('an+melden', 'inscrire', 'Ich melde meinen Sohn in der Schule an.', "J'inscris mon fils à l'école."),
 ('an+probieren', 'essayer (vêtement)', 'Sie probiert drei Kleider an.', 'Elle essaie trois robes.'),
 ('an+halten', "s'arrêter", 'Der Bus hält vor dem Krankenhaus an.', "Le bus s'arrête devant l'hôpital."),
 ('aus+gehen', 'sortir', 'Wir gehen selten unter der Woche aus.', 'Nous sortons rarement en semaine.'),
 ('aus+steigen', 'descendre', 'Alle Fahrgäste steigen am Bahnhof aus.', 'Tous les passagers descendent à la gare.'),
 ('aus+machen', 'éteindre', 'Mach bitte die Lampe aus.', "Éteins la lampe, s'il te plaît."),
 ('aus+sehen', "avoir l'air", 'Du siehst heute sehr müde aus.', "Tu as l'air très fatigué aujourd'hui."),
 ('aus+füllen', 'remplir', 'Ich fülle den Antrag online aus.', 'Je remplis la demande en ligne.'),
 ('aus+ziehen', 'enlever (un vêtement)', 'Zieh bitte deine Schuhe aus.', "Enlève tes chaussures, s'il te plaît."),
 ('aus+packen', 'déballer', 'Nach der Reise packe ich den Koffer aus.', 'Après le voyage, je défais la valise.'),
 ('aus+geben', 'dépenser', 'Wir geben viel Geld für Essen aus.', "Nous dépensons beaucoup d'argent pour la nourriture."),
 ('aus+schlafen', 'dormir tout son soûl', 'Im Urlaub schlafen wir jeden Tag aus.', 'En vacances, nous faisons la grasse matinée tous les jours.'),
 ('aus+ruhen', 'se reposer', 'Ruh dich nach der Arbeit ein bisschen aus.', 'Repose-toi un peu après le travail.'),
 ('ein+kaufen', 'faire les courses', 'Ich kaufe heute auf dem Markt ein.', "Aujourd'hui, je fais les courses au marché."),
 ('ein+laden', 'inviter', 'Wir laden die Nachbarn zum Kaffee ein.', 'Nous invitons les voisins à prendre le café.'),
 ('ein+steigen', 'monter (véhicule)', 'Die Kinder steigen in den Schulbus ein.', 'Les enfants montent dans le bus scolaire.'),
 ('ein+schlafen', "s'endormir", 'Das Kind schläft sofort ein.', "L'enfant s'endort tout de suite."),
 ('ein+packen', 'emballer', 'Ich packe warme Kleidung für die Reise ein.', "J'emporte des vêtements chauds pour le voyage."),
 ('ein+ziehen', 'emménager', 'Die neuen Mieter ziehen morgen ein.', 'Les nouveaux locataires emménagent demain.'),
 ('ein+schalten', 'allumer', 'Er schaltet die Waschmaschine ein.', 'Il met la machine à laver en marche.'),
 ('mit+kommen', 'venir avec', 'Kommst du heute Abend ins Kino mit?', 'Viens-tu avec nous au cinéma ce soir ?'),
 ('mit+nehmen', 'emporter', 'Ich nehme mein Mittagessen ins Büro mit.', "J'emporte mon déjeuner au bureau."),
 ('mit+bringen', 'apporter', 'Bring bitte deine Schwester zur Party mit.', "Amène ta sœur à la fête, s'il te plaît."),
 ('mit+machen', 'participer', 'Alle Schüler machen beim Spiel mit.', 'Tous les élèves participent au jeu.'),
 ('mit+spielen', 'jouer avec', 'Mein kleiner Bruder spielt auch mit.', 'Mon petit frère joue aussi avec nous.'),
 ('ab+fahren', 'partir', 'Unser Zug fährt von Gleis drei ab.', 'Notre train part de la voie trois.'),
 ('ab+holen', 'aller chercher', 'Der Vater holt die Tochter vom Kindergarten ab.', 'Le père va chercher sa fille à la maternelle.'),
 ('ab+geben', 'remettre', 'Ich gebe meine Hausaufgaben morgen ab.', 'Je rends mes devoirs demain.'),
 ('ab+schließen', 'fermer à clé', 'Sie schließt das Büro jeden Abend ab.', 'Elle ferme le bureau à clé tous les soirs.'),
 ('ab+sagen', 'annuler', 'Der Arzt sagt alle Termine ab.', 'Le médecin annule tous les rendez-vous.'),
 ('ab+nehmen', 'maigrir, décrocher', 'Niemand nimmt das Telefon ab.', 'Personne ne décroche le téléphone.'),
 ('zu+machen', 'fermer', 'Die Bank macht um sechzehn Uhr zu.', 'La banque ferme à seize heures.'),
 ('zu+hören', 'écouter', 'Die Schüler hören dem Lehrer zu.', 'Les élèves écoutent le professeur.'),
 ('zu+nehmen', 'grossir', 'Der Hund nimmt zu, er frisst zu viel.', 'Le chien grossit, il mange trop.'),
 ('zurück+kommen', 'revenir', 'Mein Mann kommt am Freitag zurück.', 'Mon mari revient vendredi.'),
 ('zurück+geben', 'rendre', 'Ich gebe das Buch in der Bibliothek zurück.', 'Je rends le livre à la bibliothèque.'),
 ('zurück+rufen', 'rappeler', 'Ich rufe Sie in zehn Minuten zurück.', 'Je vous rappelle dans dix minutes.'),
 ('vor+stellen', 'présenter', 'Ich stelle dir meinen Kollegen vor.', 'Je te présente mon collègue.'),
 ('vor+bereiten', 'préparer', 'Die Mutter bereitet das Frühstück vor.', 'La mère prépare le petit-déjeuner.'),
 ('vor+haben', "avoir l'intention de", 'Was hast du heute Abend vor?', "Qu'as-tu prévu ce soir ?"),
 ('vor+lesen', 'lire à voix haute', 'Der Vater liest den Kindern ein Märchen vor.', 'Le père lit un conte aux enfants.'),
 ('weg+gehen', 'partir', 'Sie geht früh von der Party weg.', 'Elle part tôt de la fête.'),
 ('weg+werfen', 'jeter', 'Ich werfe den kaputten Stuhl weg.', 'Je jette la chaise cassée.'),
 ('fern+sehen', 'regarder la télévision', 'Mein Opa sieht jeden Nachmittag fern.', 'Mon grand-père regarde la télévision tous les après-midi.'),
 ('teil+nehmen', 'participer', 'Viele Leute nehmen an dem Fest teil.', 'Beaucoup de gens participent à la fête.'),
 ('statt+finden', 'avoir lieu', 'Das Konzert findet im Stadtpark statt.', 'Le concert a lieu dans le parc municipal.'),
 ('kennen+lernen', 'faire connaissance', 'Im Kurs lerne ich nette Leute kennen.', 'Au cours, je fais la connaissance de gens sympathiques.'),
 ('um+ziehen', 'déménager', 'Wir ziehen im Sommer in eine größere Wohnung um.', 'En été, nous déménageons dans un appartement plus grand.'),
 ('um+steigen', 'changer (transport)', 'Ich steige am Hauptbahnhof in die U-Bahn um.', 'À la gare centrale, je change pour le métro.'),
 ('nach+denken', 'réfléchir', 'Er denkt lange über die Frage nach.', 'Il réfléchit longtemps à la question.'),
 ('her+kommen', 'venir ici', 'Komm bitte kurz her!', "Viens ici un instant, s'il te plaît !")]
GUIDE_PERFEKT_HABEN = [('machen', 'hat gemacht', 'Ich habe gestern meine Hausaufgaben gemacht.', "Hier, j'ai fait mes devoirs."),
 ('kaufen', 'hat gekauft', 'Wir haben ein neues Sofa gekauft.', 'Nous avons acheté un nouveau canapé.'),
 ('kochen', 'hat gekocht', 'Meine Mutter hat Suppe gekocht.', 'Ma mère a préparé de la soupe.'),
 ('lernen', 'hat gelernt', 'Er hat den ganzen Abend Deutsch gelernt.', "Il a appris l'allemand toute la soirée."),
 ('spielen', 'hat gespielt', 'Die Kinder haben im Garten gespielt.', 'Les enfants ont joué dans le jardin.'),
 ('arbeiten', 'hat gearbeitet', 'Ich habe heute zehn Stunden gearbeitet.', "J'ai travaillé dix heures aujourd'hui."),
 ('wohnen', 'hat gewohnt', 'Wir haben fünf Jahre in Douala gewohnt.', 'Nous avons habité cinq ans à Douala.'),
 ('fragen', 'hat gefragt', 'Sie hat den Polizisten nach dem Weg gefragt.', 'Elle a demandé son chemin au policier.'),
 ('sagen', 'hat gesagt', 'Was hast du gerade gesagt?', "Qu'est-ce que tu viens de dire ?"),
 ('hören', 'hat gehört', 'Hast du die Nachrichten gehört?', 'As-tu écouté les informations ?'),
 ('suchen', 'hat gesucht', 'Ich habe überall meine Brille gesucht.', "J'ai cherché mes lunettes partout."),
 ('brauchen', 'hat gebraucht', 'Für den Weg haben wir eine Stunde gebraucht.', 'Il nous a fallu une heure pour le trajet.'),
 ('zeigen', 'hat gezeigt', 'Er hat mir seine neue Wohnung gezeigt.', "Il m'a montré son nouvel appartement."),
 ('warten', 'hat gewartet', 'Wir haben lange auf den Arzt gewartet.', 'Nous avons attendu longtemps le médecin.'),
 ('kosten', 'hat gekostet', 'Das Ticket hat vierzig Euro gekostet.', 'Le billet a coûté quarante euros.'),
 ('putzen', 'hat geputzt', 'Ich habe am Morgen das Bad geputzt.', "Ce matin, j'ai nettoyé la salle de bains."),
 ('tanzen', 'hat getanzt', 'Wir haben die ganze Nacht getanzt.', 'Nous avons dansé toute la nuit.'),
 ('lachen', 'hat gelacht', 'Über den Witz haben alle gelacht.', 'Tout le monde a ri de la blague.'),
 ('weinen', 'hat geweint', 'Das Mädchen hat beim Abschied geweint.', 'La fillette a pleuré au moment des adieux.'),
 ('regnen', 'hat geregnet', 'Gestern hat es den ganzen Tag geregnet.', 'Hier, il a plu toute la journée.'),
 ('schneien', 'hat geschneit', 'In der Nacht hat es geschneit.', 'Il a neigé pendant la nuit.'),
 ('frühstücken', 'hat gefrühstückt', 'Hast du heute schon gefrühstückt?', "As-tu déjà pris ton petit-déjeuner aujourd'hui ?"),
 ('duschen', 'hat geduscht', 'Nach dem Training habe ich geduscht.', "Après l'entraînement, je me suis douché."),
 ('packen', 'hat gepackt', 'Sie hat ihren Koffer schon gepackt.', 'Elle a déjà fait sa valise.'),
 ('schicken', 'hat geschickt', 'Ich habe dir gestern ein Foto geschickt.', "Je t'ai envoyé une photo hier."),
 ('schenken', 'hat geschenkt', 'Mein Mann hat mir eine Uhr geschenkt.', "Mon mari m'a offert une montre."),
 ('danken', 'hat gedankt', 'Sie hat mir herzlich für die Hilfe gedankt.', "Elle m'a chaleureusement remercié pour l'aide."),
 ('glauben', 'hat geglaubt', 'Niemand hat ihm die Geschichte geglaubt.', "Personne n'a cru son histoire."),
 ('leben', 'hat gelebt', 'Mein Großvater hat lange im Dorf gelebt.', 'Mon grand-père a longtemps vécu au village.'),
 ('lieben', 'hat geliebt', 'Sie hat ihren Beruf immer geliebt.', 'Elle a toujours aimé son métier.'),
 ('öffnen', 'hat geöffnet', 'Wer hat das Fenster geöffnet?', 'Qui a ouvert la fenêtre ?'),
 ('rauchen', 'hat geraucht', 'Früher hat mein Onkel viel geraucht.', 'Autrefois, mon oncle fumait beaucoup.'),
 ('träumen', 'hat geträumt', 'Ich habe heute Nacht schlecht geträumt.', "J'ai fait un mauvais rêve cette nuit."),
 ('feiern', 'hat gefeiert', 'Wir haben meinen Geburtstag im Restaurant gefeiert.', 'Nous avons fêté mon anniversaire au restaurant.'),
 ('heiraten', 'hat geheiratet', 'Meine Eltern haben sehr jung geheiratet.', 'Mes parents se sont mariés très jeunes.'),
 ('bezahlen', 'hat bezahlt', 'Ich habe die Rechnung schon bezahlt.', "J'ai déjà payé la facture."),
 ('besuchen', 'hat besucht', 'Am Wochenende haben wir meine Tante besucht.', 'Ce week-end, nous avons rendu visite à ma tante.'),
 ('bestellen', 'hat bestellt', 'Er hat einen Salat und ein Wasser bestellt.', 'Il a commandé une salade et une eau.'),
 ('erzählen', 'hat erzählt', 'Oma hat uns von ihrer Kindheit erzählt.', 'Mamie nous a parlé de son enfance.'),
 ('erklären', 'hat erklärt', 'Die Lehrerin hat die Regel zweimal erklärt.', 'La professeure a expliqué la règle deux fois.'),
 ('verkaufen', 'hat verkauft', 'Wir haben unser altes Auto verkauft.', 'Nous avons vendu notre vieille voiture.'),
 ('verdienen', 'hat verdient', 'Letzten Monat hat sie gut verdient.', 'Le mois dernier, elle a bien gagné sa vie.'),
 ('vermissen', 'hat vermisst', 'Ich habe dich so sehr vermisst!', "Tu m'as tellement manqué !"),
 ('versuchen', 'hat versucht', 'Ich habe dreimal versucht, dich anzurufen.', "J'ai essayé trois fois de t'appeler."),
 ('wiederholen', 'hat wiederholt', 'Der Lehrer hat den Satz langsam wiederholt.', 'Le professeur a répété la phrase lentement.'),
 ('übersetzen', 'hat übersetzt', 'Sie hat den Brief ins Französische übersetzt.', 'Elle a traduit la lettre en français.'),
 ('studieren', 'hat studiert', 'Mein Bruder hat in Bonn studiert.', 'Mon frère a fait ses études à Bonn.'),
 ('telefonieren', 'hat telefoniert', 'Ich habe lange mit meiner Mutter telefoniert.', "J'ai longuement téléphoné à ma mère."),
 ('reparieren', 'hat repariert', 'Der Nachbar hat mein Fahrrad repariert.', 'Le voisin a réparé mon vélo.'),
 ('probieren', 'hat probiert', 'Hast du schon den Kuchen probiert?', 'As-tu déjà goûté le gâteau ?'),
 ('fotografieren', 'hat fotografiert', 'Die Touristen haben den Dom fotografiert.', 'Les touristes ont photographié la cathédrale.'),
 ('gratulieren', 'hat gratuliert', 'Alle haben mir zur Prüfung gratuliert.', "Tout le monde m'a félicité pour l'examen."),
 ('einkaufen', 'hat eingekauft', 'Ich habe heute Morgen im Supermarkt eingekauft.', "Ce matin, j'ai fait les courses au supermarché."),
 ('aufräumen', 'hat aufgeräumt', 'Die Kinder haben ihr Zimmer aufgeräumt.', 'Les enfants ont rangé leur chambre.'),
 ('aufmachen', 'hat aufgemacht', 'Wer hat die Tür aufgemacht?', 'Qui a ouvert la porte ?'),
 ('zumachen', 'hat zugemacht', 'Ich habe alle Fenster zugemacht.', "J'ai fermé toutes les fenêtres."),
 ('abholen', 'hat abgeholt', 'Papa hat mich von der Schule abgeholt.', "Papa est venu me chercher à l'école."),
 ('zuhören', 'hat zugehört', 'Du hast mir gar nicht zugehört!', "Tu ne m'as pas écouté du tout !"),
 ('aufhören', 'hat aufgehört', 'Es hat endlich aufgehört zu regnen.', 'Il a enfin arrêté de pleuvoir.'),
 ('vorbereiten', 'hat vorbereitet', 'Sie hat das Essen für die Gäste vorbereitet.', 'Elle a préparé le repas pour les invités.'),
 ('ausfüllen', 'hat ausgefüllt', 'Ich habe das Formular schon ausgefüllt.', "J'ai déjà rempli le formulaire."),
 ('essen', 'hat gegessen', 'Zu Mittag haben wir Fisch gegessen.', 'À midi, nous avons mangé du poisson.'),
 ('trinken', 'hat getrunken', 'Ich habe heute zu viel Kaffee getrunken.', "J'ai bu trop de café aujourd'hui."),
 ('schlafen', 'hat geschlafen', 'Hast du gut geschlafen?', 'As-tu bien dormi ?'),
 ('lesen', 'hat gelesen', 'Sie hat das Buch in zwei Tagen gelesen.', 'Elle a lu le livre en deux jours.'),
 ('schreiben', 'hat geschrieben', 'Ich habe meinem Chef eine E-Mail geschrieben.', "J'ai écrit un e-mail à mon chef."),
 ('sehen', 'hat gesehen', 'Hast du meinen Schlüssel gesehen?', 'As-tu vu ma clé ?'),
 ('sprechen', 'hat gesprochen', 'Wir haben über die Ferien gesprochen.', 'Nous avons parlé des vacances.'),
 ('nehmen', 'hat genommen', 'Er hat ein Taxi zum Flughafen genommen.', "Il a pris un taxi pour l'aéroport."),
 ('geben', 'hat gegeben', 'Die Lehrerin hat uns viele Hausaufgaben gegeben.', 'La professeure nous a donné beaucoup de devoirs.'),
 ('finden', 'hat gefunden', 'Ich habe zwanzig Euro auf der Straße gefunden.', "J'ai trouvé vingt euros dans la rue."),
 ('helfen', 'hat geholfen', 'Mein Freund hat mir beim Umzug geholfen.', "Mon ami m'a aidé pour le déménagement."),
 ('treffen', 'hat getroffen', 'Ich habe Anna zufällig in der Stadt getroffen.', "J'ai rencontré Anna par hasard en ville."),
 ('singen', 'hat gesungen', 'Der Chor hat sehr schön gesungen.', 'La chorale a très bien chanté.'),
 ('bringen', 'hat gebracht', 'Der Postbote hat ein Paket gebracht.', 'Le facteur a apporté un colis.'),
 ('denken', 'hat gedacht', 'Ich habe den ganzen Tag an dich gedacht.', "J'ai pensé à toi toute la journée."),
 ('wissen', 'hat gewusst', 'Das habe ich wirklich nicht gewusst.', 'Je ne le savais vraiment pas.'),
 ('kennen', 'hat gekannt', 'Ich habe ihn schon als Kind gekannt.', "Je le connaissais déjà quand j'étais enfant."),
 ('stehen', 'hat gestanden', 'Wir haben eine Stunde im Stau gestanden.', 'Nous sommes restés une heure dans les embouteillages.'),
 ('sitzen', 'hat gesessen', 'Im Kino habe ich neben Paul gesessen.', "Au cinéma, j'étais assis à côté de Paul."),
 ('liegen', 'hat gelegen', 'Das Geld hat auf dem Küchentisch gelegen.', "L'argent était sur la table de la cuisine."),
 ('tragen', 'hat getragen', 'Zur Hochzeit hat sie ein blaues Kleid getragen.', 'Pour le mariage, elle a porté une robe bleue.'),
 ('waschen', 'hat gewaschen', 'Ich habe gestern das Auto gewaschen.', "Hier, j'ai lavé la voiture."),
 ('schneiden', 'hat geschnitten', 'Der Friseur hat mir die Haare geschnitten.', "Le coiffeur m'a coupé les cheveux."),
 ('schließen', 'hat geschlossen', 'Der Bäcker hat heute früher geschlossen.', "Le boulanger a fermé plus tôt aujourd'hui."),
 ('verlieren', 'hat verloren', 'Ich habe im Bus mein Portemonnaie verloren.', "J'ai perdu mon portefeuille dans le bus."),
 ('gewinnen', 'hat gewonnen', 'Unsere Mannschaft hat zwei zu null gewonnen.', 'Notre équipe a gagné deux à zéro.'),
 ('vergessen', 'hat vergessen', 'Ich habe meinen Termin beim Zahnarzt vergessen.', "J'ai oublié mon rendez-vous chez le dentiste."),
 ('verstehen', 'hat verstanden', 'Hast du die Aufgabe verstanden?', "As-tu compris l'exercice ?"),
 ('bekommen', 'hat bekommen', 'Sie hat eine gute Note bekommen.', 'Elle a eu une bonne note.'),
 ('beginnen', 'hat begonnen', 'Der Kurs hat letzte Woche begonnen.', 'Le cours a commencé la semaine dernière.'),
 ('gefallen', 'hat gefallen', 'Der Film hat mir sehr gut gefallen.', "Le film m'a beaucoup plu."),
 ('empfehlen', 'hat empfohlen', 'Der Kellner hat uns den Fisch empfohlen.', 'Le serveur nous a recommandé le poisson.'),
 ('versprechen', 'hat versprochen', 'Du hast mir versprochen, pünktlich zu sein.', "Tu m'avais promis d'être à l'heure."),
 ('unterschreiben', 'hat unterschrieben', 'Ich habe gestern den Mietvertrag unterschrieben.', "Hier, j'ai signé le contrat de location."),
 ('anrufen', 'hat angerufen', 'Deine Schwester hat vorhin angerufen.', "Ta sœur a appelé tout à l'heure."),
 ('anfangen', 'hat angefangen', 'Das Spiel hat schon angefangen.', 'Le match a déjà commencé.'),
 ('einladen', 'hat eingeladen', 'Wir haben zwanzig Gäste eingeladen.', 'Nous avons invité vingt personnes.'),
 ('mitbringen', 'hat mitgebracht', 'Ich habe dir etwas aus Paris mitgebracht.', "Je t'ai rapporté quelque chose de Paris."),
 ('mitnehmen', 'hat mitgenommen', 'Er hat seinen Hund ins Büro mitgenommen.', 'Il a emmené son chien au bureau.'),
 ('fernsehen', 'hat ferngesehen', 'Gestern Abend haben wir lange ferngesehen.', 'Hier soir, nous avons regardé la télévision longtemps.'),
 ('anziehen', 'hat angezogen', 'Sie hat ihre neuen Schuhe angezogen.', 'Elle a mis ses nouvelles chaussures.'),
 ('ausgeben', 'hat ausgegeben', 'Im Urlaub haben wir viel Geld ausgegeben.', "En vacances, nous avons dépensé beaucoup d'argent."),
 ('teilnehmen', 'hat teilgenommen', 'Ich habe an einem Kochkurs teilgenommen.', "J'ai participé à un cours de cuisine."),
 ('stattfinden', 'hat stattgefunden', 'Die Feier hat im Garten stattgefunden.', 'La fête a eu lieu dans le jardin.'),
 ('bitten', 'hat gebeten', 'Er hat mich um Hilfe gebeten.', "Il m'a demandé de l'aide."),
 ('leihen', 'hat geliehen', 'Ich habe ihm mein Fahrrad geliehen.', 'Je lui ai prêté mon vélo.'),
 ('rufen', 'hat gerufen', 'Die Nachbarin hat die Polizei gerufen.', 'La voisine a appelé la police.'),
 ('haben', 'hat gehabt', 'Letzte Woche habe ich Fieber gehabt.', "La semaine dernière, j'ai eu de la fièvre."),
 ('backen', 'hat gebacken', 'Zum Fest hat sie drei Kuchen gebacken.', 'Pour la fête, elle a fait trois gâteaux.')]
GUIDE_PERFEKT_SEIN = [('gehen', 'ist gegangen', 'Ich bin gestern früh ins Bett gegangen.', 'Hier, je suis allé au lit tôt.'),
 ('kommen', 'ist gekommen', 'Mein Bruder ist heute zu spät gekommen.', "Mon frère est arrivé trop tard aujourd'hui."),
 ('fahren', 'ist gefahren', 'Wir sind mit dem Zug nach München gefahren.', 'Nous sommes allés à Munich en train.'),
 ('fliegen', 'ist geflogen', 'Sie ist letzte Woche nach Paris geflogen.', "Elle a pris l'avion pour Paris la semaine dernière."),
 ('laufen', 'ist gelaufen', 'Ich bin heute zehn Kilometer gelaufen.', "J'ai couru dix kilomètres aujourd'hui."),
 ('rennen', 'ist gerannt', 'Der Junge ist schnell nach Hause gerannt.', 'Le garçon a couru vite à la maison.'),
 ('schwimmen', 'ist geschwommen', 'Wir sind im Meer geschwommen.', 'Nous avons nagé dans la mer.'),
 ('reisen', 'ist gereist', 'Meine Tante ist viel durch Afrika gereist.', "Ma tante a beaucoup voyagé à travers l'Afrique."),
 ('wandern', 'ist gewandert', 'Am Sonntag sind wir im Wald gewandert.', 'Dimanche, nous avons randonné dans la forêt.'),
 ('springen', 'ist gesprungen', 'Die Katze ist auf den Tisch gesprungen.', 'Le chat a sauté sur la table.'),
 ('fallen', 'ist gefallen', 'Das Glas ist auf den Boden gefallen.', 'Le verre est tombé par terre.'),
 ('steigen', 'ist gestiegen', 'Der Preis für Benzin ist wieder gestiegen.', "Le prix de l'essence a encore augmenté."),
 ('sinken', 'ist gesunken', 'Die Temperatur ist in der Nacht gesunken.', 'La température a baissé pendant la nuit.'),
 ('bleiben', 'ist geblieben', 'Am Wochenende bin ich zu Hause geblieben.', 'Ce week-end, je suis resté à la maison.'),
 ('sein', 'ist gewesen', 'Ich bin noch nie in Berlin gewesen.', 'Je ne suis encore jamais allé à Berlin.'),
 ('werden', 'ist geworden', 'Meine Schwester ist Lehrerin geworden.', 'Ma sœur est devenue professeure.'),
 ('passieren', 'ist passiert', 'Auf der Autobahn ist ein Unfall passiert.', "Un accident s'est produit sur l'autoroute."),
 ('geschehen', 'ist geschehen', 'Zum Glück ist nichts Schlimmes geschehen.', "Heureusement, il ne s'est rien passé de grave."),
 ('sterben', 'ist gestorben', 'Unsere alte Katze ist im Winter gestorben.', 'Notre vieux chat est mort en hiver.'),
 ('wachsen', 'ist gewachsen', 'Die Tomaten im Garten sind schnell gewachsen.', 'Les tomates du jardin ont vite poussé.'),
 ('folgen', 'ist gefolgt', 'Der Hund ist mir bis zur Tür gefolgt.', "Le chien m'a suivi jusqu'à la porte."),
 ('landen', 'ist gelandet', 'Das Flugzeug ist pünktlich gelandet.', "L'avion a atterri à l'heure."),
 ('klettern', 'ist geklettert', 'Die Kinder sind auf den Baum geklettert.', "Les enfants ont grimpé à l'arbre."),
 ('reiten', 'ist geritten', 'Im Urlaub sind wir am Strand geritten.', 'En vacances, nous avons fait du cheval sur la plage.'),
 ('fließen', 'ist geflossen', 'Das Wasser ist in den Keller geflossen.', "L'eau a coulé dans la cave."),
 ('schmelzen', 'ist geschmolzen', 'Der Schnee ist schon geschmolzen.', 'La neige a déjà fondu.'),
 ('gelingen', 'ist gelungen', 'Die Überraschung ist uns gelungen.', 'Nous avons réussi la surprise.'),
 ('begegnen', 'ist begegnet', 'Ich bin meinem alten Lehrer begegnet.', "J'ai croisé mon ancien professeur."),
 ('aufstehen', 'ist aufgestanden', 'Heute bin ich um fünf Uhr aufgestanden.', "Aujourd'hui, je me suis levé à cinq heures."),
 ('aufwachen', 'ist aufgewacht', 'Ich bin mitten in der Nacht aufgewacht.', 'Je me suis réveillé en pleine nuit.'),
 ('einschlafen', 'ist eingeschlafen', 'Das Baby ist im Auto eingeschlafen.', "Le bébé s'est endormi dans la voiture."),
 ('ankommen', 'ist angekommen', 'Das Paket ist heute Morgen angekommen.', 'Le colis est arrivé ce matin.'),
 ('abfahren', 'ist abgefahren', 'Der Bus ist vor zwei Minuten abgefahren.', 'Le bus est parti il y a deux minutes.'),
 ('abfliegen', 'ist abgeflogen', 'Unser Flugzeug ist mit Verspätung abgeflogen.', 'Notre avion a décollé avec du retard.'),
 ('einsteigen', 'ist eingestiegen', 'Sie ist in den falschen Zug eingestiegen.', 'Elle est montée dans le mauvais train.'),
 ('aussteigen', 'ist ausgestiegen', 'Wir sind am Marktplatz ausgestiegen.', 'Nous sommes descendus à la place du marché.'),
 ('umsteigen', 'ist umgestiegen', 'In Frankfurt bin ich umgestiegen.', "J'ai changé à Francfort."),
 ('umziehen', 'ist umgezogen', 'Letztes Jahr sind wir nach Köln umgezogen.', "L'année dernière, nous avons déménagé à Cologne."),
 ('einziehen', 'ist eingezogen', 'Die neue Nachbarin ist gestern eingezogen.', 'La nouvelle voisine a emménagé hier.'),
 ('ausgehen', 'ist ausgegangen', 'Am Samstag sind wir tanzen ausgegangen.', 'Samedi, nous sommes sortis danser.'),
 ('weggehen', 'ist weggegangen', 'Er ist ohne Jacke weggegangen.', 'Il est parti sans veste.'),
 ('zurückkommen', 'ist zurückgekommen', 'Wann bist du aus Kamerun zurückgekommen?', 'Quand es-tu revenu du Cameroun ?'),
 ('mitkommen', 'ist mitgekommen', 'Meine Freundin ist zum Arzt mitgekommen.', 'Mon amie est venue avec moi chez le médecin.'),
 ('vorbeikommen', 'ist vorbeigekommen', 'Gestern ist mein Cousin kurz vorbeigekommen.', 'Hier, mon cousin est passé un moment.'),
 ('hereinkommen', 'ist hereingekommen', 'Der Lehrer ist leise hereingekommen.', 'Le professeur est entré sans bruit.'),
 ('spazieren gehen', 'ist spazieren gegangen', 'Nach dem Essen sind wir spazieren gegangen.', 'Après le repas, nous sommes allés nous promener.'),
 ('einkaufen gehen', 'ist einkaufen gegangen', 'Mama ist schon einkaufen gegangen.', 'Maman est déjà partie faire les courses.'),
 ('schwimmen gehen', 'ist schwimmen gegangen', 'Am Nachmittag sind die Kinder schwimmen gegangen.', "L'après-midi, les enfants sont allés nager."),
 ('aufgehen', 'ist aufgegangen', 'Die Sonne ist heute um sechs Uhr aufgegangen.', "Le soleil s'est levé à six heures aujourd'hui."),
 ('untergehen', 'ist untergegangen', 'Die Sonne ist schon untergegangen.', 'Le soleil est déjà couché.'),
 ('kaputtgehen', 'ist kaputtgegangen', 'Unser Fernseher ist kaputtgegangen.', 'Notre télévision est tombée en panne.'),
 ('durchfallen', 'ist durchgefallen', 'Mein Freund ist bei der Fahrprüfung durchgefallen.', "Mon ami a échoué à l'examen du permis de conduire."),
 ('hinfallen', 'ist hingefallen', 'Das Kind ist auf dem Spielplatz hingefallen.', "L'enfant est tombé sur l'aire de jeux."),
 ('losfahren', 'ist losgefahren', 'Wir sind um sieben Uhr losgefahren.', 'Nous sommes partis à sept heures.'),
 ('wegfahren', 'ist weggefahren', 'Die Nachbarn sind in den Urlaub weggefahren.', 'Les voisins sont partis en vacances.'),
 ('zurückfahren', 'ist zurückgefahren', 'Am Abend sind wir nach Hause zurückgefahren.', 'Le soir, nous sommes rentrés à la maison.'),
 ('verschwinden', 'ist verschwunden', 'Meine Tasche ist plötzlich verschwunden.', 'Mon sac a soudain disparu.'),
 ('erscheinen', 'ist erschienen', 'Sein neues Buch ist im März erschienen.', 'Son nouveau livre est paru en mars.'),
 ('entstehen', 'ist entstanden', 'Hier ist ein neues Stadtviertel entstanden.', 'Un nouveau quartier a vu le jour ici.'),
 ('platzen', 'ist geplatzt', 'Der Reifen vom Fahrrad ist geplatzt.', 'Le pneu du vélo a éclaté.'),
 ('explodieren', 'ist explodiert', 'In der Fabrik ist ein Tank explodiert.', "Une cuve a explosé dans l'usine."),
 ('ausrutschen', 'ist ausgerutscht', 'Ich bin auf dem nassen Boden ausgerutscht.', "J'ai glissé sur le sol mouillé."),
 ('stolpern', 'ist gestolpert', 'Er ist über einen Stein gestolpert.', 'Il a trébuché sur une pierre.'),
 ('erschrecken', 'ist erschrocken', 'Ich bin bei dem lauten Knall erschrocken.', "J'ai sursauté à cause de la forte détonation."),
 ('gefrieren', 'ist gefroren', 'Das Wasser im Eimer ist gefroren.', "L'eau dans le seau a gelé."),
 ('trocknen', 'ist getrocknet', 'Die Wäsche ist in der Sonne schnell getrocknet.', 'Le linge a vite séché au soleil.'),
 ('heilen', 'ist geheilt', 'Die Wunde ist gut geheilt.', 'La plaie a bien guéri.'),
 ('auswandern', 'ist ausgewandert', 'Mein Onkel ist nach Kanada ausgewandert.', 'Mon oncle a émigré au Canada.'),
 ('fliehen', 'ist geflohen', 'Viele Menschen sind vor dem Krieg geflohen.', 'Beaucoup de gens ont fui la guerre.'),
 ('kriechen', 'ist gekrochen', 'Das Baby ist durch das ganze Zimmer gekrochen.', 'Le bébé a rampé dans toute la pièce.')]
# (lettre, nom de la lettre « à la française », mot exemple, traduction)
GUIDE_ALPHABET = [
    ("A", "a", "der Apfel", "la pomme"), ("B", "bé", "das Brot", "le pain"), ("C", "tsé", "der Computer", "l'ordinateur"),
    ("D", "dé", "die Dose", "la boîte"), ("E", "é", "die Ente", "le canard"), ("F", "èf", "der Fisch", "le poisson"),
    ("G", "gué", "der Garten", "le jardin"), ("H", "ha", "das Haus", "la maison"), ("I", "i", "die Insel", "l'île"),
    ("J", "yot", "die Jacke", "la veste"), ("K", "ka", "die Katze", "le chat"), ("L", "èl", "die Lampe", "la lampe"),
    ("M", "èm", "die Mutter", "la mère"), ("N", "èn", "die Nase", "le nez"), ("O", "o", "das Obst", "les fruits"),
    ("P", "pé", "das Papier", "le papier"), ("Q", "kou", "die Quelle", "la source"), ("R", "èr", "der Regen", "la pluie"),
    ("S", "ès", "die Sonne", "le soleil"), ("T", "té", "der Tisch", "la table"), ("U", "ou", "die Uhr", "la montre"),
    ("V", "faou", "der Vater", "le père"), ("W", "vé", "das Wasser", "l'eau"), ("X", "iks", "das Xylofon", "le xylophone"),
    ("Y", "upsilone", "das Yoga", "le yoga"), ("Z", "tsèt", "die Zeit", "le temps"),
    ("Ä", "è (a tréma)", "der Käse", "le fromage"), ("Ö", "eu (o tréma)", "das Öl", "l'huile"),
    ("Ü", "u (u tréma)", "die Tür", "la porte"), ("ß", "ès-tsèt (s dur)", "die Straße", "la rue"),
]
_GUIDE_ALPHA_FR = {"Ä": "A tréma", "Ö": "O tréma", "Ü": "U tréma", "ß": "Eszett, le S dur"}
# (graphie, comment ça se prononce, mot exemple, traduction)
GUIDE_SOUNDS = [
    ("ei", "se dit « aï »", "das Ei", "l'œuf"), ("ie", "se dit « i » long", "die Liebe", "l'amour"),
    ("eu", "se dit « oï »", "der Freund", "l'ami"), ("äu", "se dit « oï »", "die Häuser", "les maisons"),
    ("au", "se dit « aou »", "das Auto", "la voiture"), ("ch", "son soufflé, comme dans « ich »", "ich", "je"),
    ("ch", "son raclé après a, o, u", "das Buch", "le livre"), ("sch", "se dit « ch »", "die Schule", "l'école"),
    ("sp", "au début d'un mot : « chp »", "der Sport", "le sport"), ("st", "au début d'un mot : « cht »", "die Stadt", "la ville"),
    ("z", "se dit « ts »", "der Zug", "le train"), ("v", "se dit souvent « f »", "der Vogel", "l'oiseau"),
    ("w", "se dit « v »", "der Wein", "le vin"), ("j", "se dit « y »", "das Jahr", "l'année"),
    ("qu", "se dit « kv »", "die Qualität", "la qualité"), ("h", "après une voyelle : il allonge la voyelle", "der Stuhl", "la chaise"),
    ("s", "devant une voyelle : « z »", "die Sonne", "le soleil"), ("ig", "à la fin d'un mot : « ich »", "billig", "bon marché"),
    ("pf", "on prononce les deux lettres", "das Pferd", "le cheval"), ("tsch", "se dit « tch »", "Deutsch", "allemand"),
]

def _guide_playlists():
    """Playlists du guide. Règle stricte : « fr » = texte FRANÇAIS (voix française), « de » = texte ALLEMAND (voix allemande)."""
    pls = {}
    pls["Guide : l'alphabet allemand"] = [
        {"fr": "La lettre " + _GUIDE_ALPHA_FR.get(L, L), "de": f"{L}, wie {w}"} for L, _n, w, _f in GUIDE_ALPHABET]
    for title, rows in GUIDE_VERBS:
        pls["Guide verbes : " + title] = [{"fr": f"{vfr} : {sfr}", "de": f"{v}. {sde}"} for v, vfr, sde, sfr in rows]
    pls["Guide : verbes séparables"] = [
        {"fr": f"{vfr} : {sfr}", "de": f"{v.replace('+', '')}. {sde}"} for v, vfr, sde, sfr in GUIDE_TRENNBAR]
    pls["Guide : Perfekt avec haben"] = [{"fr": sfr, "de": f"{v}, {pp}. {sde}"} for v, pp, sde, sfr in GUIDE_PERFEKT_HABEN]
    pls["Guide : Perfekt avec sein"] = [{"fr": sfr, "de": f"{v}, {pp}. {sde}"} for v, pp, sde, sfr in GUIDE_PERFEKT_SEIN]
    return pls

@app.route("/guide")
@login_required
def guide():
    small = "padding:4px 10px;font-size:12px;"
    pls = _guide_playlists()

    def row(head_html, sde, sfr, de_say, key):
        # 🇩🇪 = allemand seul (voix allemande) ; ▶ = phrase française (voix française) puis phrase allemande (voix allemande)
        return f"""
        <div class="gd-row" data-k="{h(key.lower(), quote=True)}">
          <div class="gd-main">{head_html}
            <span class="gd-ex">🇩🇪 {h(sde)}</span>
            <span class="gd-ex nk-fr">🇫🇷 {h(sfr)}</span>
          </div>
          <div class="gd-btns">
            {say_btn("🇩🇪", "de", "", de_say, css="btn ghost", style=small)}
            {say_btn("▶", "pair", sfr, sde, css="btn ghost", style=small)}
          </div>
        </div>"""

    def head(title, sub, pl_title, anchor):
        return f"""
        <div class="card nk-group" id="{anchor}" style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;border-left:5px solid var(--warn);">
          <div><h2 style="margin:0">{h(title)}</h2>
          <p style="color:var(--muted);font-size:13px;margin:4px 0 0 0;">{h(sub)}</p></div>
          {playlist_btn("▶ Écouter cette partie", "guide", pl_title, css="btn ok")}
        </div>"""

    # --- 1. alphabet ---
    letters = ""
    for L, nm, w, wfr in GUIDE_ALPHABET:
        shown = L if L == "ß" else f"{L} {L.lower()}"
        letters += f"""
        <div class="gd-letter"><span class="big">{h(shown)}</span>
          <span class="nk-fr">se dit « {h(nm)} »</span><br><b>{h(w)}</b> <span class="nk-fr">— {h(wfr)}</span><br>
          {say_btn("🔊 " + h(L), "de", "", L, css="btn ghost", style=small)}
          {say_btn("🔊 mot", "de", "", w, css="btn ghost", style=small)}
        </div>"""
    sounds = ""
    for g, how, w, wfr in GUIDE_SOUNDS:
        sounds += f"""
        <div class="nk-pair"><div class="nk-txt"><b>{h(g)}</b> <span class="nk-fr">— {h(how)}</span> · <b>{h(w)}</b> <span class="nk-fr">— {h(wfr)}</span></div>
          {say_btn("🔊", "de", "", w, css="btn ghost", style=small)}</div>"""
    alpha_html = head("L'alphabet allemand", "26 lettres + Ä, Ö, Ü et ß — avec un mot pour chaque lettre",
                      "Guide : l'alphabet allemand", "gd-alpha") + f"""
        <div class="nomakk-section"><h3>Les 30 lettres</h3>
          <div class="gd-alpha">{letters}</div>
          <div class="explanation">💡 Pour épeler ton nom au téléphone, dis les lettres une par une. Exemple : N-A-T-H-O.</div>
        </div>
        <div class="nomakk-section"><h3>Les sons particuliers</h3>
          <div class="content nk-content">{sounds}</div>
          <div class="explanation">💡 En allemand, on prononce presque toutes les lettres. Retiens surtout : ei = « aï », ie = « i », eu = « oï », w = « v », z = « ts ».</div>
        </div>"""

    # --- 2. les 450 verbes ---
    n_verbs = sum(len(rows) for _t, rows in GUIDE_VERBS)
    verbs_html = f"""
        <div class="card nk-group" id="gd-verbes" style="border-left:5px solid var(--warn);">
          <h2 style="margin:0">Les {n_verbs} verbes les plus utilisés</h2>
          <p style="color:var(--muted);font-size:13px;margin:4px 0 10px 0;">Chaque verbe a sa phrase de la vie de tous les jours. 🇩🇪 = écouter l'allemand · ▶ = français puis allemand.</p>
          <input type="text" id="gd-search" placeholder="🔎 Chercher un verbe (allemand ou français)…" autocomplete="off" style="margin:0;">
          <p id="gd-count" style="color:var(--muted);font-size:12px;margin:6px 0 0 0;"></p>
        </div>"""
    num = 0
    for gi, (title, rows) in enumerate(GUIDE_VERBS):
        body_rows = ""
        for v, vfr, sde, sfr in rows:
            num += 1
            body_rows += row(f'<b>{num}. {h(v)}</b> <span class="nk-fr">— {h(vfr)}</span>', sde, sfr, f"{v}. {sde}", f"{v} {vfr}")
        verbs_html += f"""
        <div class="nomakk-section gd-vgroup" id="gd-v{gi + 1}">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
            <h3 style="margin:0">{h(title)}</h3>
            {playlist_btn("▶ Écouter", "guide", "Guide verbes : " + title, css="btn ok")}
          </div>
          <div class="content nk-content">{body_rows}</div>
        </div>"""

    # --- 3. verbes séparables ---
    tr_rows = ""
    for v, vfr, sde, sfr in GUIDE_TRENNBAR:
        pre, _, base = v.partition("+")
        tr_rows += row(f'<b><span class="gd-pp">{h(pre)}</span>{h(base)}</b> <span class="nk-fr">— {h(vfr)}</span>',
                       sde, sfr, f"{pre + base}. {sde}", f"{pre + base} {vfr}")
    trenn_html = head("Les verbes séparables (trennbare Verben)", f"{len(GUIDE_TRENNBAR)} verbes avec une phrase chacun",
                      "Guide : verbes séparables", "gd-trennbar") + f"""
        <div class="nomakk-section"><h3>La règle</h3>
          <div class="content nk-content">
            <div class="nk-line">Un verbe séparable = un petit mot (la particule) + un verbe : <b><span class="gd-pp">auf</span>stehen</b>, <b><span class="gd-pp">an</span>rufen</b>, <b><span class="gd-pp">ein</span>kaufen</b>.</div>
            <div class="nk-line">1) Au présent, le verbe est conjugué en 2ᵉ position et la particule part <b>à la fin</b> de la phrase : Ich <b>stehe</b> um sechs Uhr <b>auf</b>.</div>
            <div class="nk-line">2) Avec un verbe de modalité, le verbe reste entier à la fin : Ich muss um sechs Uhr <b>aufstehen</b>.</div>
            <div class="nk-line">3) Au Perfekt, « ge » se met au milieu : auf<b>ge</b>standen, an<b>ge</b>rufen, ein<b>ge</b>kauft.</div>
            <div class="nk-line">Particules séparables courantes : ab, an, auf, aus, ein, mit, vor, zu, zurück, weg, her, fern, teil, statt, um, nach.</div>
            <div class="nk-line">Attention : be-, ge-, er-, ver-, zer-, ent-, emp-, miss- ne se séparent jamais (besuchen, verstehen, erzählen).</div>
          </div>
        </div>
        <div class="nomakk-section"><h3>Les verbes et leurs phrases</h3>
          <div class="content nk-content">{tr_rows}</div>
          <div class="explanation">💡 La particule (en couleur) porte l'accent : on dit AUFstehen, ANrufen, EINkaufen.</div>
        </div>"""

    # --- 4. Perfekt ---
    def perfekt_rows(data):
        out = ""
        for v, pp, sde, sfr in data:
            out += row(f'<b>{h(v)}</b> → <span class="gd-pp">{h(pp)}</span>', sde, sfr, f"{v}, {pp}. {sde}", f"{v} {pp}")
        return out
    n_perf = len(GUIDE_PERFEKT_HABEN) + len(GUIDE_PERFEKT_SEIN)
    perfekt_html = f"""
        <div class="card nk-group" id="gd-perfekt" style="border-left:5px solid var(--warn);">
          <h2 style="margin:0">Le Perfekt (le passé) avec haben et sein</h2>
          <p style="color:var(--muted);font-size:13px;margin:4px 0 0 0;">{n_perf} exemples : {len(GUIDE_PERFEKT_HABEN)} avec haben, {len(GUIDE_PERFEKT_SEIN)} avec sein</p>
        </div>
        <div class="nomakk-section"><h3>La règle</h3>
          <div class="content nk-content">
            <div class="nk-line">Perfekt = <b>haben</b> ou <b>sein</b> conjugué (2ᵉ position) + <b>participe passé</b> à la fin : Ich <b>habe</b> Brot <b>gekauft</b>. Ich <b>bin</b> nach Hause <b>gegangen</b>.</div>
            <div class="nk-line">• <b>haben</b> : la grande majorité des verbes (machen, essen, kaufen, sehen…).</div>
            <div class="nk-line">• <b>sein</b> : les verbes de <b>déplacement</b> (gehen, fahren, fliegen, kommen), de <b>changement d'état</b> (aufwachen, einschlafen, wachsen, sterben) et trois exceptions : <b>sein, bleiben, werden</b>.</div>
            <div class="nk-line">• Participe régulier : ge + radical + t → machen : <b>gemacht</b>. Participe irrégulier : ge + radical + en → sehen : <b>gesehen</b>.</div>
            <div class="nk-line">• Verbes en -ieren et verbes en be-, ver-, er- : pas de « ge » → studiert, besucht, verkauft, erzählt.</div>
            <div class="nk-line">• Verbes séparables : « ge » au milieu → eingekauft, aufgestanden.</div>
          </div>
        </div>
        <div class="nomakk-section" id="gd-haben">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
            <h3 style="margin:0">Perfekt avec haben — {len(GUIDE_PERFEKT_HABEN)} exemples</h3>
            {playlist_btn("▶ Écouter", "guide", "Guide : Perfekt avec haben", css="btn ok")}
          </div>
          <div class="content nk-content">{perfekt_rows(GUIDE_PERFEKT_HABEN)}</div>
        </div>
        <div class="nomakk-section" id="gd-sein">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
            <h3 style="margin:0">Perfekt avec sein — {len(GUIDE_PERFEKT_SEIN)} exemples</h3>
            {playlist_btn("▶ Écouter", "guide", "Guide : Perfekt avec sein", css="btn ok")}
          </div>
          <div class="content nk-content">{perfekt_rows(GUIDE_PERFEKT_SEIN)}</div>
          <div class="explanation">💡 Astuce : si le verbe exprime un déplacement d'un point A à un point B ou un changement d'état, utilise sein. Sinon, haben.</div>
        </div>"""

    chips = ('<a class="nk-chip" href="#gd-alpha">🔤 Alphabet</a>'
             f'<a class="nk-chip" href="#gd-verbes">📗 {n_verbs} verbes</a>'
             '<a class="nk-chip" href="#gd-trennbar">✂️ Verbes séparables</a>'
             '<a class="nk-chip" href="#gd-haben">⏪ Perfekt haben</a>'
             '<a class="nk-chip" href="#gd-sein">⏪ Perfekt sein</a>')
    script = """
    <script>
    (function(){
      var inp = document.getElementById('gd-search');
      var cnt = document.getElementById('gd-count');
      if (!inp) return;
      inp.addEventListener('input', function(){
        var q = inp.value.trim().toLowerCase();
        var shown = 0;
        var groups = document.querySelectorAll('.gd-vgroup');
        for (var g = 0; g < groups.length; g++) {
          var rows = groups[g].querySelectorAll('.gd-row');
          var any = false;
          for (var i = 0; i < rows.length; i++) {
            var ok = !q || (rows[i].getAttribute('data-k') || '').indexOf(q) !== -1;
            rows[i].style.display = ok ? '' : 'none';
            if (ok) { any = true; shown++; }
          }
          groups[g].style.display = any ? '' : 'none';
        }
        cnt.textContent = q ? (shown + ' verbe(s) trouvé(s)') : '';
      });
    })();
    </script>
    """
    body = f"""
    <h1>Guide 📘</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      Ton aide-mémoire : l'alphabet, les {n_verbs} verbes les plus utilisés au quotidien avec une phrase pour chacun,
      les verbes séparables et le Perfekt avec haben et sein ({n_perf} exemples).
      L'allemand est toujours lu par la voix allemande et le français par la voix française.
    </p>
    <div class="nk-chips">{chips}</div>
    {alpha_html}
    {verbs_html}
    {trenn_html}
    {perfekt_html}
    {playlist_data_script({"guide": pls})}
    {script}
    """
    return page(layout("Guide", body, {"is_admin": session.get("is_admin")}))


@app.route("/playlists")
@login_required
def playlists():
    db = get_db()
    
    cats_lessons = db.execute("SELECT DISTINCT category FROM lessons ORDER BY category").fetchall()
    playlist_data_lessons = {}
    for c in cats_lessons:
        items = db.execute("SELECT french, german FROM lessons WHERE category=? ORDER BY order_index", (c["category"],)).fetchall()
        playlist_data_lessons[c["category"]] = [{"fr": i["french"], "de": i["german"]} for i in items]

    cats_vocab = db.execute("SELECT DISTINCT category FROM vocab ORDER BY category").fetchall()
    playlist_data_vocab = {}
    for c in cats_vocab:
        items = db.execute("SELECT french, german FROM vocab WHERE category=? ORDER BY id", (c["category"],)).fetchall()
        playlist_data_vocab[c["category"]] = [{"fr": i["french"], "de": i["german"]} for i in items]

    d_rows = db.execute("SELECT * FROM dialogues ORDER BY id").fetchall()
    playlist_data_dialogues = {}
    for r in d_rows:
        lines = json.loads(r["lines_json"])
        playlist_data_dialogues[r["title"]] = [{"fr": l["fr"], "de": l["de"]} for l in lines]
        
    playlist_data_speak = {}
    speak_rows = db.execute("SELECT key, title, items_json FROM speak_playlists WHERE kind='speak'").fetchall()
    for r in speak_rows:
        playlist_data_speak[r["title"]] = json.loads(r["items_json"])

    playlist_data_essentials = {}
    ess_rows = db.execute("SELECT key, title, items_json FROM speak_playlists WHERE kind='essentials'").fetchall()
    for r in ess_rows:
        playlist_data_essentials[r["title"]] = json.loads(r["items_json"])

    playlist_data_nomakk = {}
    nomakk_rows = db.execute("SELECT key, title, items_json FROM nomakk_playlist").fetchall()
    for r in nomakk_rows:
        playlist_data_nomakk[r["title"]] = json.loads(r["items_json"])

    order_l = [r["category"] for r in db.execute(
        "SELECT category FROM lessons GROUP BY category ORDER BY MIN(order_index), MIN(id)").fetchall()]
    order_v = [r["category"] for r in db.execute(
        "SELECT category FROM vocab GROUP BY category ORDER BY MIN(id)").fetchall()]
    order_d = [r["title"] for r in d_rows]

    n_lessons = sum(len(v) for v in playlist_data_lessons.values())
    n_vocab = sum(len(v) for v in playlist_data_vocab.values())
    n_dialogues = sum(len(v) for v in playlist_data_dialogues.values())

    js_payload = ({
        "lessons": playlist_data_lessons,
        "vocab": playlist_data_vocab,
        "dialogues": playlist_data_dialogues,
        "speak": playlist_data_speak,
        "essentials": playlist_data_essentials,
        "nomakk": playlist_data_nomakk,
        "order": {"lessons": order_l, "vocab": order_v, "dialogues": order_d}
    })

    cards_all = f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tous les cours</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_lessons} phrases en un seul bloc.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "lessons", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tout le vocabulaire</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_vocab} mots en un seul bloc.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "vocab", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tous les dialogues</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_dialogues} répliques.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "dialogues", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center; background: #D4F5E3;">
            <div>
                <h3 style="margin:0">Tout NATHO (Phrases + Vocab + Dialogues)</h3>
                <p style="color:#1E7A45;font-size:14px;margin:4px 0 0 0">{n_lessons + n_vocab + n_dialogues} éléments.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "mix", css="btn ok")}
        </div>
    """

    cards_speak = ""
    for theme_title, items in playlist_data_speak.items():
        cards_speak += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(theme_title)}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{len(items)} phrases complètes.</p>
            </div>
            {playlist_btn("▶ Playlist", "speak", theme_title, css="btn ok")}
        </div>
        """

    cards_ess = ""
    for title, items in playlist_data_essentials.items():
        cards_ess += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(title)}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{len(items)} paires FR → DE.</p>
            </div>
            {playlist_btn("▶ Playlist", "essentials", title, css="btn ok")}
        </div>
        """

    cards_nomakk = ""
    for title, items in playlist_data_nomakk.items():
        cards_nomakk += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center; border-left:5px solid var(--warn);">
            <div>
                <h3 style="margin:0">{h(title)}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{len(items)} phrases (sections + exemples).</p>
            </div>
            {playlist_btn("▶ Playlist", "nomakk", title, css="btn ok")}
        </div>
        """

    cards_lessons = ""
    for c in cats_lessons:
        cards_lessons += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(c['category'])}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Leçons de cours.</p>
            </div>
            {playlist_btn("▶ Playlist", "lessons", c['category'], css="btn ok")}
        </div>
        """

    cards_vocab = ""
    for c in cats_vocab:
        cards_vocab += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(c['category'])}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Mots de vocabulaire.</p>
            </div>
            {playlist_btn("▶ Playlist", "vocab", c['category'], css="btn")}
        </div>
        """
        
    cards_dialogues = ""
    for c in order_d:
        cards_dialogues += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(c)}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Dialogue.</p>
            </div>
            {playlist_btn("▶ Playlist", "dialogues", c, css="btn")}
        </div>
        """

    body = f"""
    <h1>Playlists Audio 🎵</h1>
    <p style="margin-bottom:20px;color:var(--muted);">Le mode Spotify de NATHO. Choisis ce que tu veux écouter.</p>

    <h2>🎧 Blocs complets</h2>
    {cards_all}

    <h2 style="margin-top:30px;">⚖️ NOM/AKK/DATIV/GENITIV</h2>
    {cards_nomakk}

    <h2 style="margin-top:30px;">🗨️ Apprendre à parler (par thème)</h2>
    {cards_speak}

    <h2 style="margin-top:30px;">📌 Essentiels A1</h2>
    {cards_ess}

    <h2 style="margin-top:30px;">🗣️ Dialogues du quotidien</h2>
    {cards_dialogues}

    <h2 style="margin-top:30px;">📚 Playlists de Cours</h2>
    {cards_lessons}

    <h2 style="margin-top:30px;">📖 Playlists de Vocabulaire</h2>
    {cards_vocab}

    {playlist_data_script(js_payload)}
    """
    return page(layout("Playlists", body, {"is_admin": session.get("is_admin")}))

@app.route("/progress")
@login_required
def progress():
    db = get_db()
    rows = db.execute("""
      SELECT l.id, l.category, l.german, l.french,
             COALESCE(p.listened,0) as listened,
             COALESCE(p.completed,0) as completed
      FROM lessons l LEFT JOIN progress p
        ON p.lesson_id=l.id AND p.user_id=?
      ORDER BY l.category, l.order_index
    """, (session["user_id"],)).fetchall()
    rows_html = ""
    for r in rows:
        badge = '<span class="badge done">✔</span>' if r["completed"] else (
                '<span class="badge todo">⏯</span>' if r["listened"] else '—')
        play_btn = say_btn("▶ Écouter", "pair", r["french"], r["german"],
                           css="btn ghost", style="padding:6px 12px;font-size:12px")
        rows_html += f"<tr><td>{h(r['category'])}</td><td><b>{h(r['german'])}</b></td><td>{h(r['french'])}</td><td>{badge}</td><td>{play_btn}</td></tr>"

    def _goethe_parse(ex):
        try:
            data = json.loads(ex["result_json"])
        except Exception:
            return "—", False, "Erreur"
        mod = str(data.get("module", "Examen"))
        ok = data.get("score", 0) >= max(1, data.get("total", 1))
        detail = data.get("detail") or ("%s%%" % data["pct"] if "pct" in data else "")
        label = ("✔ Réussi" if ok else "✘ À revoir") + (" · " + str(detail) if detail else "")
        return mod, ok, label

    g_all = db.execute("SELECT * FROM goethe_exam WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    g_html = ""
    g_stats = {}
    for n_ex, ex in enumerate(g_all):
        mod, ok, label = _goethe_parse(ex)
        st = g_stats.setdefault(mod, [0, 0])
        st[1] += 1
        st[0] += 1 if ok else 0
        if n_ex < 15:
            g_html += f"<tr><td>{h(str(ex['taken_at']))}</td><td>{h(mod)}</td><td>{h(label)}</td></tr>"

    if not g_html:
        g_html = "<tr><td colspan='3'>Aucun examen Goethe passé pour le moment.</td></tr>"
    g_stats_html = "".join(
        f'<div class="stat"><div class="num">{a}/{b}</div><div class="lbl">{h(m)} réussis</div></div>'
        for m, (a, b) in g_stats.items())
    if g_stats_html:
        g_stats_html = f'<div class="stat-grid" style="margin-bottom:14px">{g_stats_html}</div>'

    body = f"""
    <h1>Mes progrès</h1>
    <div class="card">
      <h2>Leçons</h2>
      <table><thead><tr><th>Catégorie</th><th>Allemand</th><th>Français</th><th>État</th><th>Audio</th></tr></thead>
      <tbody>{rows_html}</tbody></table>
    </div>
    <div class="card">
      <h2>Mes examens Goethe</h2>
      {g_stats_html}
      <table><thead><tr><th>Date</th><th>Module</th><th>Résultat</th></tr></thead><tbody>{g_html}</tbody></table>
    </div>
    """
    return page(layout("Progrès", body, {"is_admin": session.get("is_admin")}))

# ---------------------------------------------------------
# PAGES LÉGALES
# ---------------------------------------------------------
@app.route("/politique")
def politique():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    body = """
    <h1>Politique de confidentialité</h1>
    <div class="card">
        <h2>1. Collecte des données</h2>
        <p>NATHO collecte uniquement votre nom, votre adresse email et vos résultats d'apprentissage. Ces données sont strictement confidentielles et ne sont jamais vendues à des tiers.</p>
        <h2>2. Neferti et la mémoire</h2>
        <p>Neferti mémorise vos informations (nom, ville, animal, etc.) pour personnaliser vos conversations. Chaque compte a sa mémoire isolée et privée : aucun utilisateur ne voit les données d'un autre.</p>
        <h2>3. Sécurité</h2>
        <p>Les mots de passe ne sont jamais stockés en clair : ils sont protégés par un hachage salé. Nous vous recommandons d'utiliser un mot de passe fort et unique.</p>
        <h2>4. Vos droits</h2>
        <p>Conformément au RGPD, vous pouvez supprimer votre compte (et donc votre progression, vos résultats et la mémoire Neferti) à tout moment depuis la page « Mon compte ».</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return page(layout("Politique de confidentialité", body, user))

@app.route("/cgu")
def cgu():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    body = """
    <h1>Conditions Générales d'Utilisation</h1>
    <div class="card">
        <h2>1. Objet</h2>
        <p>NATHO est une plateforme d'apprentissage de l'allemand destinée aux débutants (Niveau A1).</p>
        <h2>2. Propriété intellectuelle</h2>
        <p>L'ensemble du contenu est la propriété exclusive de NATHO.</p>
        <h2>3. Utilisation</h2>
        <p>Vous vous engagez à ne pas partager vos identifiants de connexion.</p>
        <h2>4. Responsabilité</h2>
        <p>NATHO ne délivre pas de certificat officiel Goethe. Les examens proposés sont des simulations.</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return page(layout("CGU", body, user))

@app.route("/mentions")
def mentions():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    body = """
    <h1>Mentions Légales</h1>
    <div class="card">
        <p><strong>Éditeur :</strong> NATHO Platform</p>
        <p><strong>Contact :</strong> admin@natho.com</p>
        <p><strong>Hébergement :</strong> Railway (Cloud)</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return page(layout("Mentions légales", body, user))

# ---------------------------------------------------------
# EXAMEN GOETHE A1
# ---------------------------------------------------------
HOREN_QUESTIONS = [
    {"audio": "Guten Tag! Ich möchte eine Fahrkarte nach Berlin kaufen.", "q": "Que veut acheter la personne ?", "opts": ["Un billet pour Berlin", "Un café", "Un livre"], "ans": "0"},
    {"audio": "Wo ist der Bahnhof, bitte?", "q": "Que cherche la personne ?", "opts": ["La gare", "L'hôpital", "La banque"], "ans": "0"},
    {"audio": "Ich hätte gern ein Wasser, bitte.", "q": "Que commande la personne ?", "opts": ["De l'eau", "Du vin", "Un café"], "ans": "0"},
    {"audio": "Wie viel kostet dieses Hemd?", "q": "Que demande la personne ?", "opts": ["Le prix d'une chemise", "L'heure", "Le chemin"], "ans": "0"},
    {"audio": "Können Sie mir helfen?", "q": "Que demande la personne ?", "opts": ["De l'aide", "De l'argent", "Un taxi"], "ans": "0"},
    {"audio": "Ich bin krank, ich brauche einen Arzt.", "q": "De quoi a besoin la personne ?", "opts": ["D'un médecin", "D'un avocat", "D'un professeur"], "ans": "0"},
    {"audio": "Wann fährt der Zug nach Paris?", "q": "Quelle est la question ?", "opts": ["L'heure du train pour Paris", "Le prix du train", "Le quai du train"], "ans": "0"},
    {"audio": "Mein Name ist Thomas.", "q": "Quel est le nom de la personne ?", "opts": ["Thomas", "Pierre", "Paul"], "ans": "0"},
    {"audio": "Ich wohne in Berlin.", "q": "Où habite la personne ?", "opts": ["À Berlin", "À Paris", "À Londres"], "ans": "0"},
    {"audio": "Ich suche die Toilette.", "q": "Que cherche la personne ?", "opts": ["Les toilettes", "La sortie", "L'entrée"], "ans": "0"}
]

LESEN_QUESTIONS = [
    {"text": "Hallo Anna, ich komme heute später, weil ich noch einkaufen muss. Wir treffen uns um 19 Uhr im Restaurant. Bis später, Tom.", "q": "Pourquoi Tom arrive-t-il plus tard ?", "opts": ["Il doit faire des courses", "Il est malade", "Il travaille"], "ans": "0"},
    {"text": "Liebe Maria, vielen Dank für die Einladung. Ich komme gern zu deiner Party am Samstag. Bis bald!", "q": "Que répond l'auteur ?", "opts": ["Il accepte l'invitation", "Il refuse l'invitation", "Il ne sait pas"], "ans": "0"},
    {"text": "Achtung: Der Supermarkt ist heute wegen Renovierung geschlossen.", "q": "Pourquoi le supermarché est-il fermé ?", "opts": ["Pour rénovation", "Pour les vacances", "Pour une grève"], "ans": "0"},
    {"text": "Ich heiße Sophie. Ich bin 25 Jahre alt und komme aus Frankreich. Ich arbeite als Lehrerin.", "q": "Quel est le métier de Sophie ?", "opts": ["Professeure", "Médecin", "Ingénieure"], "ans": "0"},
    {"text": "Bitte rufen Sie mich unter der Nummer 0123456789 an.", "q": "Que demande la personne ?", "opts": ["D'appeler un numéro", "D'envoyer un mail", "D'écrire une lettre"], "ans": "0"},
    {"text": "Das Hotel ist sehr schön und das Frühstück ist inklusive.", "q": "Qu'est-ce qui est inclus ?", "opts": ["Le petit-déjeuner", "Le dîner", "La piscine"], "ans": "0"},
    {"text": "Ich kann heute nicht kommen, ich habe keine Zeit. Morgen ist besser.", "q": "Pourquoi la personne ne vient pas ?", "opts": ["Elle n'a pas le temps", "Elle est malade", "Elle est en vacances"], "ans": "0"},
    {"text": "Der Kurs beginnt um 9 Uhr und endet um 12 Uhr.", "q": "Quand commence le cours ?", "opts": ["À 9 heures", "À 10 heures", "À 12 heures"], "ans": "0"},
    {"text": "Entschuldigung, wo ist die Apotheke? Ich brauche Medikamente.", "q": "Que cherche la personne ?", "opts": ["La pharmacie", "La boulangerie", "La banque"], "ans": "0"},
    {"text": "Ich habe zwei Kinder, einen Jungen und ein Mädchen.", "q": "Combien d'enfants a la personne ?", "opts": ["Deux", "Un", "Trois"], "ans": "0"}
]

SCHREIBEN_QUESTIONS = [
    {"q": "Écris un message à un ami pour l'inviter à dîner ce soir. (Hallo, ...)", "min_words": 8,
     "must": [["hallo", "liebe", "guten tag"], ["einlad", "komm"], ["abend", "essen", "heute"]],
     "model": "Hallo Paul, kommst du heute Abend zum Essen zu mir? Ich koche Reis und Fisch. Bis später, Anna"},
    {"q": "Écris un message pour dire que tu es malade et que tu ne peux pas venir au cours. (Hallo, ...)", "min_words": 8,
     "must": [["hallo", "liebe", "guten tag"], ["krank"], ["kurs", "unterricht", "schule", "komm"]],
     "model": "Hallo Frau Weber, ich bin heute krank. Ich kann nicht zum Kurs kommen. Bis bald, Samuel"},
    {"q": "Écris un message pour demander le prix d'un billet de train pour Munich. (Guten Tag, ...)", "min_words": 8,
     "must": [["guten tag", "hallo", "sehr geehrte"], ["fahrkarte", "ticket", "zug"], ["münchen"], ["kost", "preis"]],
     "model": "Guten Tag, was kostet eine Fahrkarte nach München? Ich möchte am Samstag fahren. Vielen Dank"},
    {"q": "Écris un message pour t'excuser d'être en retard au rendez-vous. (Entschuldigung, ...)", "min_words": 8,
     "must": [["entschuldig", "tut mir leid"], ["spät", "zu spät"], ["bus", "zug", "komm", "warte", "bin"]],
     "model": "Entschuldigung, ich komme zu spät. Der Bus hat Verspätung. Ich bin in zehn Minuten da"},
    {"q": "Écris un message pour remercier ton ami pour le cadeau. (Liebe/r ..., ...)", "min_words": 8,
     "must": [["liebe", "lieber", "hallo"], ["danke", "dank"], ["geschenk"]],
     "model": "Lieber Paul, vielen Dank für das Geschenk. Es gefällt mir sehr. Bis bald, Anna"}
]

SPRECHEN_QUESTIONS = [
    {"q": "Présente-toi : Dis ton nom, ton pays, ta ville et ta langue maternelle.", "example": "Hallo! Ich heiße Thomas. Ich komme aus Kamerun. Ich wohne in Douala. Ich lerne Deutsch.",
     "pattern": "Ich heiße ... Ich komme aus ... Ich wohne in ..."},
    {"q": "Épelle ton nom de famille lentement à voix haute.", "example": "M-A-R-T-I-N",
     "pattern": ""},
    {"q": "Dis à voix haute que tu aimes le café et que tu n'aimes pas le thé.", "example": "Ich mag Kaffee, aber ich mag keinen Tee.",
     "pattern": "Ich mag Kaffee ... ich mag keinen Tee"},
    {"q": "Dis les jours de la semaine en allemand.", "example": "Montag, Dienstag, Mittwoch, Donnerstag, Freitag, Samstag, Sonntag.",
     "pattern": "Montag Dienstag Mittwoch Donnerstag Freitag Samstag Sonntag"},
    {"q": "Commande un café et un croissant dans un restaurant à voix haute.", "example": "Ich hätte gern einen Kaffee und ein Croissant.",
     "pattern": "Ich hätte gern einen Kaffee und ein Croissant / Ich möchte einen Kaffee und ein Croissant"}
]

# +40 questions par module (contenu ajouté en v4.1)
HOREN_EXTRA = [
    {"audio": "Der Zug nach Hamburg fährt um halb acht von Gleis drei.", "q": "À quelle heure part le train ?", "opts": ["À 7h30", "À 8h30", "À 3h00"], "ans": "0"},
    {"audio": "Das Brot kostet zwei Euro fünfzig.", "q": "Combien coûte le pain ?", "opts": ["2,50 euros", "5,20 euros", "1,50 euro"], "ans": "0"},
    {"audio": "Hallo, hier ist Lisa. Ich kann heute nicht kommen, ich habe Fieber.", "q": "Pourquoi Lisa ne peut-elle pas venir ?", "opts": ["Elle a de la fièvre", "Elle a un examen", "Elle est en retard"], "ans": "0"},
    {"audio": "Morgen regnet es in München, und es ist nur zehn Grad kalt.", "q": "Quel temps fera-t-il demain à Munich ?", "opts": ["Il pleuvra", "Il fera beau et chaud", "Il neigera"], "ans": "0"},
    {"audio": "Das Konzert beginnt am Freitag um zwanzig Uhr.", "q": "Quel jour a lieu le concert ?", "opts": ["Vendredi", "Samedi", "Jeudi"], "ans": "0"},
    {"audio": "Ich esse zum Frühstück ein Brötchen mit Käse und trinke einen Tee.", "q": "Que boit la personne au petit-déjeuner ?", "opts": ["Du thé", "Du café", "Du lait"], "ans": "0"},
    {"audio": "Meine Schwester heißt Julia. Sie ist Ärztin und arbeitet im Krankenhaus.", "q": "Où travaille Julia ?", "opts": ["À l'hôpital", "À l'école", "Dans un magasin"], "ans": "0"},
    {"audio": "Entschuldigung, ich habe ein Zimmer für zwei Nächte reserviert.", "q": "Pour combien de nuits la chambre est-elle réservée ?", "opts": ["Deux", "Une", "Quatre"], "ans": "0"},
    {"audio": "Die Bank ist neben dem Supermarkt, gleich links.", "q": "Où se trouve la banque ?", "opts": ["À côté du supermarché", "En face de la gare", "Derrière l'école"], "ans": "0"},
    {"audio": "Der Bus Nummer fünf fährt zum Flughafen.", "q": "Où va le bus numéro 5 ?", "opts": ["À l'aéroport", "À la gare", "À l'hôpital"], "ans": "0"},
    {"audio": "Ich fahre am Sonntag mit meiner Familie nach Hause.", "q": "Avec qui la personne rentre-t-elle chez elle ?", "opts": ["Avec sa famille", "Avec ses collègues", "Avec un ami"], "ans": "0"},
    {"audio": "Frau Schmidt, Ihr Termin beim Zahnarzt ist am Dienstag um zehn Uhr.", "q": "Chez qui Mme Schmidt a-t-elle rendez-vous ?", "opts": ["Chez le dentiste", "Chez le coiffeur", "Chez le médecin généraliste"], "ans": "0"},
    {"audio": "Ich möchte zwei Kilo Äpfel und eine Flasche Milch, bitte.", "q": "Que veut acheter la personne ?", "opts": ["Des pommes et du lait", "Du pain et du fromage", "Des oranges et de l'eau"], "ans": "0"},
    {"audio": "Das Museum ist montags geschlossen.", "q": "Quel jour le musée est-il fermé ?", "opts": ["Le lundi", "Le dimanche", "Le mardi"], "ans": "0"},
    {"audio": "Mein Handy ist kaputt. Ich brauche ein neues.", "q": "Quel est le problème de la personne ?", "opts": ["Son téléphone est cassé", "Elle a perdu ses clés", "Son ordinateur est lent"], "ans": "0"},
    {"audio": "Tom spielt am Wochenende Fußball mit seinen Freunden.", "q": "Que fait Tom le week-end ?", "opts": ["Il joue au football", "Il va au cinéma", "Il fait du vélo"], "ans": "0"},
    {"audio": "Wir haben heute Pizza, Salat und Suppe. Was möchten Sie trinken?", "q": "Que demande le serveur ?", "opts": ["Ce que le client veut boire", "Combien de personnes sont là", "Comment le client veut payer"], "ans": "0"},
    {"audio": "Hier ist der Anrufbeantworter von Doktor Weber. Die Praxis ist von acht bis zwölf Uhr geöffnet.", "q": "Jusqu'à quelle heure le cabinet est-il ouvert ?", "opts": ["Jusqu'à 12h", "Jusqu'à 8h", "Jusqu'à 14h"], "ans": "0"},
    {"audio": "Ich bin Peter und ich komme aus Österreich. Ich spreche Deutsch und ein bisschen Englisch.", "q": "De quel pays vient Peter ?", "opts": ["D'Autriche", "D'Allemagne", "De Suisse"], "ans": "0"},
    {"audio": "Das Hotel hat ein Schwimmbad, aber kein Restaurant.", "q": "Qu'y a-t-il dans l'hôtel ?", "opts": ["Une piscine", "Un restaurant", "Un jardin"], "ans": "0"},
    {"audio": "Mein Geburtstag ist am fünften Mai.", "q": "Quelle est la date d'anniversaire de la personne ?", "opts": ["Le 5 mai", "Le 15 mai", "Le 5 mars"], "ans": "0"},
    {"audio": "Bitte nehmen Sie die zweite Straße rechts, dann sehen Sie die Post.", "q": "Que doit faire la personne pour trouver la poste ?", "opts": ["Prendre la deuxième rue à droite", "Prendre la deuxième rue à gauche", "Aller tout droit"], "ans": "0"},
    {"audio": "Papa kommt heute spät nach Hause, er arbeitet bis neun Uhr.", "q": "Jusqu'à quelle heure papa travaille-t-il ?", "opts": ["Jusqu'à 21h", "Jusqu'à 19h", "Jusqu'à 6h"], "ans": "0"},
    {"audio": "Die Kinder haben morgen keine Schule, weil Feiertag ist.", "q": "Pourquoi les enfants n'ont-ils pas école demain ?", "opts": ["C'est un jour férié", "Ils sont malades", "Les professeurs font grève"], "ans": "0"},
    {"audio": "Ich nehme den Fisch, und meine Frau nimmt das Hähnchen.", "q": "Que prend la femme ?", "opts": ["Du poulet", "Du poisson", "Un steak"], "ans": "0"},
    {"audio": "Das T-Shirt gefällt mir, aber es ist zu klein. Haben Sie es in Größe M?", "q": "Quel est le problème avec le T-shirt ?", "opts": ["Il est trop petit", "Il est trop cher", "Il est trop grand"], "ans": "0"},
    {"audio": "Mein Bruder wohnt in Köln und arbeitet bei einer Bank.", "q": "Où travaille le frère ?", "opts": ["Dans une banque", "Dans un hôpital", "Dans une école"], "ans": "0"},
    {"audio": "Achtung, liebe Fahrgäste! Der Zug nach Wien hat zwanzig Minuten Verspätung.", "q": "Quel est le problème annoncé ?", "opts": ["Le train a du retard", "Le train est annulé", "Le train est complet"], "ans": "0"},
    {"audio": "Kommst du heute Abend mit ins Kino? Der Film beginnt um acht.", "q": "Que propose la personne ?", "opts": ["Aller au cinéma", "Aller au restaurant", "Aller à la piscine"], "ans": "0"},
    {"audio": "Ich schlafe jeden Tag bis sieben Uhr und dann dusche ich.", "q": "Jusqu'à quelle heure la personne dort-elle ?", "opts": ["Jusqu'à 7h", "Jusqu'à 6h", "Jusqu'à 9h"], "ans": "0"},
    {"audio": "Das Zimmer kostet vierzig Euro pro Nacht, mit Frühstück.", "q": "Combien coûte la chambre par nuit ?", "opts": ["40 euros", "14 euros", "60 euros"], "ans": "0"},
    {"audio": "Hier ist Frau Braun. Ich komme morgen nicht zur Arbeit, mein Sohn ist krank.", "q": "Pourquoi Mme Braun ne vient-elle pas au travail ?", "opts": ["Son fils est malade", "Elle est en vacances", "Sa voiture est en panne"], "ans": "0"},
    {"audio": "Im Sommer fahren wir an das Meer, im Winter fahren wir in die Berge.", "q": "Que font-ils en hiver ?", "opts": ["Ils vont à la montagne", "Ils vont à la mer", "Ils restent à la maison"], "ans": "0"},
    {"audio": "Ich lerne Deutsch, weil ich in Deutschland arbeiten möchte.", "q": "Pourquoi la personne apprend-elle l'allemand ?", "opts": ["Pour travailler en Allemagne", "Pour voyager en vacances", "Pour parler avec sa famille"], "ans": "0"},
    {"audio": "Der Apfelkuchen ist heute im Café nur drei Euro.", "q": "Qu'est-ce qui coûte trois euros ?", "opts": ["Un gâteau aux pommes", "Une glace", "Une pizza"], "ans": "0"},
    {"audio": "Entschuldigung, ist dieser Platz frei? Ja, bitte, setzen Sie sich.", "q": "Que répond la deuxième personne ?", "opts": ["Que la place est libre", "Que la place est prise", "Qu'elle part tout de suite"], "ans": "0"},
    {"audio": "Ich bin Lehrerin. Meine Schule ist klein, und ich habe zwanzig Schüler.", "q": "Combien d'élèves a la personne ?", "opts": ["Vingt", "Douze", "Trente"], "ans": "0"},
    {"audio": "Die Bäckerei öffnet um sechs Uhr morgens.", "q": "Quand la boulangerie ouvre-t-elle ?", "opts": ["À 6h du matin", "À 6h du soir", "À 8h du matin"], "ans": "0"},
    {"audio": "Gute Nacht, Oma! Morgen besuche ich dich.", "q": "À qui la personne parle-t-elle ?", "opts": ["À sa grand-mère", "À sa mère", "À sa tante"], "ans": "0"},
    {"audio": "Mir ist kalt. Kann ich bitte das Fenster schließen?", "q": "Que demande la personne ?", "opts": ["De fermer la fenêtre", "D'ouvrir la porte", "D'allumer la lumière"], "ans": "0"}
]

LESEN_EXTRA = [
    {"text": "Liebe Eva, am Samstag mache ich eine Party. Sie beginnt um 18 Uhr. Kommst du? Viele Grüße, Jan", "q": "Quel jour a lieu la fête ?", "opts": ["Samedi", "Dimanche", "Vendredi"], "ans": "0"},
    {"text": "Sonderangebot: Äpfel, 1 Kilo nur 1,99 Euro!", "q": "Quel est le prix des pommes ?", "opts": ["1,99 euro le kilo", "1,99 euro la pièce", "9,99 euros le kilo"], "ans": "0"},
    {"text": "Praxis Dr. Müller. Sprechzeiten: Montag bis Freitag von 8 bis 12 Uhr.", "q": "Quand le cabinet est-il ouvert ?", "opts": ["Du lundi au vendredi matin", "Le samedi matin", "Tous les après-midi"], "ans": "0"},
    {"text": "Hallo Paul, ich bin im Café am Markt. Ich warte schon 20 Minuten. Wo bist du?", "q": "Que fait l'auteur du message ?", "opts": ["Il attend Paul au café", "Il est chez lui", "Il est dans le train"], "ans": "0"},
    {"text": "Zimmer zu vermieten: 2 Zimmer, Küche, Bad, 450 Euro im Monat.", "q": "Combien coûte le logement ?", "opts": ["450 euros par mois", "540 euros par mois", "450 euros par semaine"], "ans": "0"},
    {"text": "Heute gibt es im Restaurant: Suppe, Schnitzel mit Kartoffeln und Eis. Alles zusammen 9 Euro.", "q": "Que comprend le menu du jour ?", "opts": ["Soupe, escalope et glace", "Salade et poisson", "Pizza et gâteau"], "ans": "0"},
    {"text": "Liebe Frau Klein, mein Sohn ist krank und kann heute nicht in die Schule kommen. Mit freundlichen Grüßen, Anna Berger", "q": "Pourquoi le fils ne vient-il pas à l'école ?", "opts": ["Il est malade", "Il a un rendez-vous", "Il est en vacances"], "ans": "0"},
    {"text": "Das Schwimmbad ist im August täglich von 9 bis 20 Uhr geöffnet.", "q": "En quel mois ces horaires sont-ils valables ?", "opts": ["En août", "En juillet", "En juin"], "ans": "0"},
    {"text": "Wir ziehen am 1. Mai um. Die neue Adresse ist Lindenstraße 8 in Leipzig.", "q": "Que va faire cette famille le 1er mai ?", "opts": ["Elle va déménager", "Elle va partir en vacances", "Elle va acheter une voiture"], "ans": "0"},
    {"text": "Hallo Lena, danke für deine Karte aus Italien. Bei uns ist das Wetter schlecht, es regnet jeden Tag.", "q": "Quel temps fait-il chez l'auteur ?", "opts": ["Il pleut tous les jours", "Il fait beau", "Il neige"], "ans": "0"},
    {"text": "Fahrrad zu verkaufen. Fast neu, nur 120 Euro. Bitte schreiben Sie an max@mail.de.", "q": "Que vend-on ?", "opts": ["Un vélo", "Une voiture", "Une table"], "ans": "0"},
    {"text": "Die Bibliothek ist sonntags geschlossen. Am Samstag ist sie bis 14 Uhr geöffnet.", "q": "Quand la bibliothèque est-elle fermée ?", "opts": ["Le dimanche", "Le samedi", "Le lundi"], "ans": "0"},
    {"text": "Ich suche eine Wohnung in Hamburg. Ich habe einen Hund, und ich arbeite in der Stadt.", "q": "Que cherche la personne ?", "opts": ["Un appartement", "Un travail", "Un chien"], "ans": "0"},
    {"text": "Liebe Oma, ich bin gut in Wien angekommen. Das Hotel ist klein, aber sehr sauber. Bis bald! Tim", "q": "Où se trouve Tim ?", "opts": ["À Vienne", "À Berlin", "À Zurich"], "ans": "0"},
    {"text": "Der Deutschkurs findet montags und mittwochs von 18 bis 20 Uhr statt.", "q": "Quels jours a lieu le cours d'allemand ?", "opts": ["Lundi et mercredi", "Mardi et jeudi", "Lundi et vendredi"], "ans": "0"},
    {"text": "Verzeihung, ich bin leider zu spät. Mein Bus ist nicht gekommen.", "q": "Pourquoi la personne est-elle en retard ?", "opts": ["Le bus n'est pas venu", "Elle s'est réveillée tard", "Elle a perdu ses clés"], "ans": "0"},
    {"text": "Mein Hobby ist Kochen. Am Wochenende koche ich oft für meine Freunde.", "q": "Que fait la personne le week-end ?", "opts": ["Elle cuisine pour ses amis", "Elle fait du sport", "Elle va au cinéma"], "ans": "0"},
    {"text": "Achtung! Parken verboten. Hier ist die Einfahrt von der Schule.", "q": "Que signifie cette affiche ?", "opts": ["Il est interdit de se garer", "Le parking est gratuit", "C'est l'entrée du parc"], "ans": "0"},
    {"text": "Hallo Sara, kannst du mir bitte das Buch mitbringen? Ich brauche es morgen für den Kurs. Danke! Ali", "q": "Que demande Ali à Sara ?", "opts": ["D'apporter le livre", "De prêter de l'argent", "De l'appeler"], "ans": "0"},
    {"text": "Das Hemd kostet 25 Euro. Die Hose kostet 40 Euro.", "q": "Quel article est le plus cher ?", "opts": ["Le pantalon", "La chemise", "Ils ont le même prix"], "ans": "0"},
    {"text": "Wir fahren im Juli nach Spanien. Wir bleiben zwei Wochen und fliegen von Frankfurt.", "q": "Combien de temps restent-ils en Espagne ?", "opts": ["Deux semaines", "Deux jours", "Un mois"], "ans": "0"},
    {"text": "Der Zug nach Köln fährt heute von Gleis 7 und nicht von Gleis 3.", "q": "De quel quai part le train aujourd'hui ?", "opts": ["Du quai 7", "Du quai 3", "Du quai 5"], "ans": "0"},
    {"text": "Hallo Mama, ich habe Hunger. Ich gehe jetzt in die Küche und mache Nudeln.", "q": "Que va faire l'auteur ?", "opts": ["Préparer des pâtes", "Aller au restaurant", "Acheter du pain"], "ans": "0"},
    {"text": "Gesucht: Verkäuferin für Bäckerei, Montag bis Freitag, ab 6 Uhr morgens.", "q": "Quelle personne cherche-t-on ?", "opts": ["Une vendeuse", "Une cuisinière", "Une secrétaire"], "ans": "0"},
    {"text": "Lieber Karl, herzlichen Glückwunsch zum Geburtstag! Ich wünsche dir alles Gute. Deine Nina", "q": "Pourquoi Nina écrit-elle à Karl ?", "opts": ["Pour son anniversaire", "Pour son mariage", "Pour le remercier"], "ans": "0"},
    {"text": "Bitte leise sein! Hier schlafen die Kinder.", "q": "Que demande cette affiche ?", "opts": ["D'être silencieux", "De fermer la porte", "D'éteindre la lumière"], "ans": "0"},
    {"text": "Ich bin Student und wohne mit zwei Freunden in einer Wohnung. Die Miete ist günstig.", "q": "Avec qui habite l'étudiant ?", "opts": ["Avec deux amis", "Avec ses parents", "Il habite seul"], "ans": "0"},
    {"text": "Im Park gibt es heute ein Fest für Kinder. Es beginnt um 15 Uhr, der Eintritt ist frei.", "q": "Que dit le texte sur l'entrée ?", "opts": ["Elle est gratuite", "Elle coûte 5 euros", "Elle coûte 2 euros"], "ans": "0"},
    {"text": "Guten Tag, ich möchte einen Tisch für vier Personen reservieren, heute um 20 Uhr.", "q": "Pour combien de personnes est la réservation ?", "opts": ["Quatre", "Deux", "Six"], "ans": "0"},
    {"text": "Mein Chef ist nett, aber ich habe viel Arbeit. Ich arbeite von 8 bis 17 Uhr.", "q": "À quelle heure la personne finit-elle de travailler ?", "opts": ["À 17h", "À 8h", "À 15h"], "ans": "0"},
    {"text": "Es ist Winter. Heute schneit es, und es ist minus fünf Grad kalt.", "q": "Quel temps fait-il aujourd'hui ?", "opts": ["Il neige et il fait froid", "Il fait chaud", "Il y a du soleil"], "ans": "0"},
    {"text": "Die Apotheke am Bahnhof hat auch am Sonntag geöffnet.", "q": "Quelle pharmacie est ouverte le dimanche ?", "opts": ["Celle de la gare", "Celle de l'école", "Aucune"], "ans": "0"},
    {"text": "Hallo Julia, ich habe zwei Karten für das Kino. Hast du am Freitag Zeit? Liebe Grüße, Mia", "q": "Que propose Mia à Julia ?", "opts": ["Aller au cinéma vendredi", "Aller au théâtre samedi", "Étudier ensemble"], "ans": "0"},
    {"text": "Das Zimmer hat ein Bett, einen Tisch und eine Lampe. Es hat keinen Fernseher.", "q": "Qu'est-ce qui manque dans la chambre ?", "opts": ["La télévision", "La lampe", "La table"], "ans": "0"},
    {"text": "Mein Vater ist 50 Jahre alt. Er ist Taxifahrer und fährt jeden Tag durch die Stadt.", "q": "Quel est le métier du père ?", "opts": ["Chauffeur de taxi", "Pilote", "Cuisinier"], "ans": "0"},
    {"text": "Entschuldigung, wir haben keine Milch mehr. Möchten Sie lieber Saft?", "q": "Que propose-t-on au client ?", "opts": ["Du jus", "Du café", "De l'eau"], "ans": "0"},
    {"text": "Wir sind am Strand. Das Meer ist warm, und die Sonne scheint. Es ist toll! Eure Lea", "q": "Où se trouve Lea ?", "opts": ["À la plage", "À la montagne", "En ville"], "ans": "0"},
    {"text": "Der Brief ist für Herrn Weber. Er wohnt im dritten Stock.", "q": "À quel étage habite M. Weber ?", "opts": ["Au troisième", "Au premier", "Au rez-de-chaussée"], "ans": "0"},
    {"text": "Ab nächster Woche beginnt die Schule schon um 7.45 Uhr und nicht mehr um 8 Uhr.", "q": "À quelle heure l'école commencera-t-elle la semaine prochaine ?", "opts": ["À 7h45", "À 8h", "À 8h45"], "ans": "0"},
    {"text": "Ich spreche Französisch und Englisch. Deutsch lerne ich noch.", "q": "Que dit la personne de l'allemand ?", "opts": ["Elle l'apprend encore", "Elle le parle déjà bien", "Elle ne veut pas l'apprendre"], "ans": "0"}
]

SCHREIBEN_EXTRA = [
    {"q": "Écris un message à une amie pour l'inviter à ta fête d'anniversaire samedi. (Liebe Anna, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["einlad", "party", "feier"], ["samstag", "geburtstag"]], "model": "Liebe Anna, ich habe am Samstag Geburtstag und mache eine Party. Ich möchte dich gern einladen. Kommst du um 18 Uhr zu mir? Viele Grüße, Tom"},
    {"q": "Écris un message à ton professeur pour dire que tu arrives en retard au cours parce que ton bus ne roule pas. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "liebe"], ["entschuldig", "leider", "tut mir leid"], ["spät", "bus"], ["kurs", "unterricht", "schule"]], "model": "Guten Tag, entschuldigen Sie bitte, ich komme heute leider zu spät zum Kurs. Mein Bus fährt nicht. Ich bin um zehn Uhr da. Danke und viele Grüße, Paul"},
    {"q": "Écris un message au cabinet médical : tu es malade et tu veux un rendez-vous. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "sehr geehrte"], ["krank", "fieber", "schmerz"], ["termin", "zeit"], ["arzt", "praxis"]], "model": "Guten Tag, ich bin krank und brauche einen Termin. Ich habe Kopfschmerzen und Fieber. Kann ich heute zum Arzt kommen? Danke, Maria Weber"},
    {"q": "Écris un message pour remercier une amie pour le dîner d'hier soir. (Liebe Sophie, ...)", "min_words": 12, "must": [["hallo", "liebe", "guten tag"], ["danke", "dank"], ["essen", "abend", "einladung"]], "model": "Liebe Sophie, vielen Dank für das Essen gestern Abend. Es war sehr lecker und der Abend war schön. Bis bald, Lena"},
    {"q": "Écris un e-mail à un hôtel pour demander le prix d'une chambre double pour trois nuits. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte", "hallo"], ["zimmer", "doppelzimmer"], ["preis", "kost"], ["nacht", "nächte"]], "model": "Guten Tag, ich möchte ein Doppelzimmer für drei Nächte buchen. Was kostet das Zimmer pro Nacht? Ist das Frühstück im Preis? Danke, Karl Meier"},
    {"q": "Écris un message à un restaurant pour réserver une table pour cinq personnes samedi soir. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "sehr geehrte"], ["tisch", "reserv"], ["personen", "uhr"], ["samstag", "abend"]], "model": "Guten Tag, ich möchte einen Tisch für fünf Personen reservieren. Wir kommen am Samstag um 19 Uhr. Vielen Dank, Familie Braun"},
    {"q": "Écris un message pour annuler un rendez-vous chez le coiffeur. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo", "liebe"], ["termin", "zeit"], ["absag", "nicht kommen", "leider"]], "model": "Guten Tag, ich habe morgen einen Termin bei Ihnen. Leider kann ich nicht kommen. Ich muss den Termin absagen. Danke, Eva Klein"},
    {"q": "Écris un message à un magasin pour demander si la veste existe dans une autre taille. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo", "sehr geehrte"], ["jacke", "mantel"], ["größ", "gross", "groß"]], "model": "Guten Tag, die Jacke im Schaufenster gefällt mir sehr. Haben Sie die Jacke auch in einer anderen Größe? Ich brauche Größe M. Danke, Ali"},
    {"q": "Écris un message à un ami pour lui dire que tu as déménagé dans une nouvelle ville. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["umgezogen", "umzug", "wohne", "neu"], ["stadt", "wohnung", "haus"]], "model": "Hallo Max, ich habe Neuigkeiten. Ich bin umgezogen und wohne jetzt in Köln. Die Stadt ist groß und meine Wohnung ist schön. Komm bald zu Besuch! Dein Jonas"},
    {"q": "Écris une carte postale à ta famille depuis tes vacances. (Liebe Familie, ...)", "min_words": 14, "must": [["liebe", "hallo", "grüße"], ["urlaub", "ferien", "meer", "hotel"], ["wetter", "sonn", "schön"]], "model": "Liebe Familie, viele Grüße aus dem Urlaub! Das Hotel ist toll und das Meer ist ganz nah. Das Wetter ist schön und die Sonne scheint jeden Tag. Bis bald, Eure Nina"},
    {"q": "Écris un e-mail à ton voisin : sa musique est trop forte le soir et tu demandes de la baisser. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "lieber"], ["laut", "musik", "lärm"], ["bitte", "könnten", "leiser"]], "model": "Guten Tag Herr Schulz, Ihre Musik ist abends sehr laut. Ich kann nicht schlafen. Könnten Sie bitte leiser sein? Vielen Dank, Frau Bauer"},
    {"q": "Écris un message à une collègue pour l'inviter à prendre un café demain. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "guten tag"], ["kaffee", "café"], ["morgen", "übermorgen"], ["zeit", "kommen", "komm"]], "model": "Hallo Petra, hast du morgen Zeit? Ich möchte dich zu einem Kaffee einladen. Wir können um drei Uhr im Café gehen. Bis morgen, Sara"},
    {"q": "Écris un message à un ami : tu as perdu tes clés et tu demandes de l'aide. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "guten tag"], ["schlüssel", "tür"], ["verloren", "weg"]], "model": "Hallo Tim, ich habe meinen Schlüssel verloren. Ich kann nicht in die Wohnung gehen. Kannst du mir bitte helfen? Danke, Jan"},
    {"q": "Écris un message pour t'excuser auprès d'un ami car tu as oublié son anniversaire. (Lieber Paul, ...)", "min_words": 12, "must": [["lieber", "liebe", "hallo"], ["entschuldig", "tut mir leid", "leider"], ["geburtstag", "vergessen"]], "model": "Lieber Paul, es tut mir leid, ich habe deinen Geburtstag vergessen. Ich wünsche dir nachträglich alles Gute. Wir feiern bald zusammen! Dein Leo"},
    {"q": "Écris un message à un ami pour proposer d'aller faire les courses samedi. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["einkauf", "kaufen", "markt"], ["samstag", "abend"], ["kommst", "zeit"]], "model": "Hallo Ben, am Samstag gehe ich einkaufen. Ich brauche Brot, Obst und Milch. Kommst du mit? Hast du Zeit? Gruß, Marco"},
    {"q": "Écris un message à ta mère pour dire à quelle heure ton train arrive et demander qu'elle vienne te chercher. (Hallo Mama, ...)", "min_words": 14, "must": [["hallo", "liebe"], ["zug", "bahnhof"], ["uhr", "zeit", "früh"], ["abhol", "kommen", "bitte"]], "model": "Hallo Mama, mein Zug kommt um 15 Uhr am Bahnhof an. Kannst du mich bitte abholen? Ich habe zwei Taschen. Danke, Lisa"},
    {"q": "Écris un message pour remercier ton professeur d'allemand pour son aide. (Liebe Frau Roth, ...)", "min_words": 12, "must": [["liebe", "guten tag", "sehr geehrte"], ["danke", "dank"], ["hilfe", "geholfen", "deutsch"]], "model": "Liebe Frau Roth, vielen Dank für Ihre Hilfe. Ich lerne jetzt besser Deutsch. Der Kurs ist sehr gut. Viele Grüße, Samir"},
    {"q": "Écris un e-mail à une école de langues pour demander des informations sur un cours pour débutants. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte", "hallo"], ["kurs", "deutsch"], ["anfänger", "a1", "deutsch"], ["preis", "kost", "wann", "beginn"]], "model": "Guten Tag, ich möchte einen Deutschkurs für Anfänger machen. Wann beginnt der Kurs und was kostet er? Danke für Ihre Antwort, Ibrahim"},
    {"q": "Écris un message à un ami : tu as faim et tu proposes de manger une pizza ce soir. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["pizza", "restaurant"], ["abend", "heute"], ["hunger", "essen", "komm"]], "model": "Hallo Sven, ich habe Hunger. Wollen wir heute Abend eine Pizza essen? Ich kenne ein gutes Restaurant. Kommst du mit? Gruß, Dani"},
    {"q": "Écris un message à ton chef : tu es malade et tu ne peux pas travailler aujourd'hui. (Guten Morgen, ...)", "min_words": 12, "must": [["guten morgen", "guten tag", "hallo", "sehr geehrte"], ["krank", "fieber", "schmerz"], ["arbeit", "heute", "morgen"]], "model": "Guten Morgen Herr Wolf, ich bin krank und kann heute nicht zur Arbeit kommen. Ich gehe zum Arzt. Ich rufe Sie morgen an. Danke, Eva Berg"},
    {"q": "Écris un message à ta voisine pour l'inviter à un barbecue dimanche. (Liebe Frau Lang, ...)", "min_words": 14, "must": [["hallo", "liebe", "guten tag"], ["grill", "essen", "einlad"], ["sonntag", "samstag", "freitag"]], "model": "Liebe Frau Lang, am Sonntag grille ich im Garten. Ich möchte Sie gern einladen. Wir essen um 13 Uhr. Kommen Sie bitte? Viele Grüße, Hans Roth"},
    {"q": "Écris un message à la réception d'un hôtel pour demander à quelle heure est le petit-déjeuner. (Guten Tag, ...)", "min_words": 10, "must": [["guten tag", "hallo"], ["frühstück", "essen"], ["wann", "uhr"], ["hotel", "zimmer"]], "model": "Guten Tag, ich wohne in Zimmer 12 in Ihrem Hotel. Wann gibt es das Frühstück? Bis wie viel Uhr ist es offen? Danke, Herr Nguyen"},
    {"q": "Écris un message à un ami pour lui présenter ta famille. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["familie", "schwester", "bruder", "mutter", "vater"], ["wohn", "heiß", "alt"]], "model": "Hallo Tom, ich erzähle dir von meiner Familie. Ich habe eine Schwester und einen Bruder. Meine Schwester heißt Anna und ist zwölf Jahre alt. Wir wohnen in Yaoundé. Dein Paul"},
    {"q": "Écris un message à un collègue : tu ne peux pas venir à la réunion de 15 heures, tu proposes 16 heures. (Hallo, ...)", "min_words": 14, "must": [["hallo", "guten tag", "liebe"], ["termin", "treffen", "besprechung"], ["uhr", "zeit", "früh"], ["leider", "nicht", "kann"]], "model": "Hallo Frank, ich kann leider nicht zum Treffen um 15 Uhr kommen. Ist 16 Uhr auch möglich? Ich habe dann Zeit. Danke, Julia"},
    {"q": "Écris un message à un ami pour lui demander de te prêter un livre. (Hallo, ...)", "min_words": 10, "must": [["hallo", "liebe", "lieber"], ["buch", "leihen"], ["leih", "brauche", "bitte"]], "model": "Hallo Chris, ich brauche das Buch für den Deutschkurs. Kannst du mir das Buch bitte leihen? Ich bringe es nächste Woche zurück. Danke, Emma"},
    {"q": "Écris un message à un ami pour parler de ton travail. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["arbeit", "beruf", "job"], ["gern", "gut", "nett", "viel"]], "model": "Hallo Lukas, wie geht es dir? Ich habe eine neue Arbeit in einem Hotel. Die Kollegen sind nett und ich arbeite gern dort. Ich habe aber viel zu tun. Dein Karim"},
    {"q": "Écris un message à un magasin en ligne : ton colis n'est pas arrivé après une semaine. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte", "hallo"], ["paket", "bestellung"], ["nicht", "leider", "kein"], ["woche", "tag", "bitte"]], "model": "Guten Tag, ich habe vor einer Woche ein Paket bestellt. Das Paket ist leider noch nicht da. Können Sie bitte prüfen, wo es ist? Danke, Frau Fischer"},
    {"q": "Écris un message à la gare : tu as perdu ton téléphone dans le train. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo", "sehr geehrte"], ["handy", "telefon"], ["verloren", "gefunden", "bahnhof", "zug"]], "model": "Guten Tag, ich habe mein Handy im Zug verloren. Es ist schwarz und hat eine rote Hülle. Haben Sie es gefunden? Danke, Herr Adler"},
    {"q": "Écris un message à un ami malade pour lui souhaiter un bon rétablissement. (Lieber Peter, ...)", "min_words": 12, "must": [["lieber", "liebe", "hallo"], ["gute besserung", "besser", "krank"], ["gesund", "hoffe", "besuch"]], "model": "Lieber Peter, ich höre, dass du krank bist. Gute Besserung! Ich hoffe, du bist bald wieder gesund. Ich besuche dich am Sonntag. Dein Max"},
    {"q": "Écris un message à ta famille pour souhaiter un joyeux Noël et une bonne année. (Liebe Familie, ...)", "min_words": 12, "must": [["liebe", "hallo"], ["frohe", "weihnacht", "neues jahr", "wünsche"], ["gesund", "glück", "alles gute"]], "model": "Liebe Familie, ich wünsche euch frohe Weihnachten und ein gutes neues Jahr. Bleibt gesund und glücklich! Alles Gute, Peter"},
    {"q": "Écris un message à un ami pour fixer un rendez-vous à la gare à une certaine heure. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["bahnhof", "zug"], ["treffen", "abholen", "warte"], ["uhr", "zeit", "früh"]], "model": "Hallo Ali, wir treffen uns morgen am Bahnhof. Der Zug fährt um neun Uhr. Ich warte vor dem Eingang. Bis morgen, Daniel"},
    {"q": "Écris un message pour souhaiter un bon anniversaire à une amie. (Liebe Hanna, ...)", "min_words": 10, "must": [["liebe", "hallo"], ["glückwunsch", "geburtstag", "alles gute"], ["wünsche", "geschenk", "feiern"]], "model": "Liebe Hanna, herzlichen Glückwunsch zum Geburtstag! Ich wünsche dir alles Gute und viel Glück. Wir feiern bald zusammen. Deine Mia"},
    {"q": "Écris un e-mail à un propriétaire pour demander des informations sur un appartement et proposer une visite. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte"], ["wohnung", "miete"], ["miete", "kost", "preis"], ["besichtig", "termin", "anschauen"]], "model": "Guten Tag, ich interessiere mich für die Wohnung in der Lindenstraße. Wie hoch ist die Miete? Kann ich die Wohnung am Samstag besichtigen? Danke, Herr Yilmaz"},
    {"q": "Écris un message à un ami pour lui dire quel temps il fait chez toi. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["wetter", "regn", "sonn", "kalt"], ["hier", "bei uns", "heute"]], "model": "Hallo Tom, wie ist das Wetter bei dir? Hier regnet es seit drei Tagen und es ist kalt. Ich bleibe heute zu Hause. Dein Ben"},
    {"q": "Écris un message à une collègue pour raconter ton week-end. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "guten morgen"], ["wochenende", "samstag", "sonntag"], ["fahr", "gehe", "spiel", "besuch", "mach"]], "model": "Hallo Nora, am Wochenende war es schön. Am Samstag besuche ich meine Eltern. Am Sonntag gehe ich mit Freunden in den Park und wir spielen Fußball. Und du? Gruß, Mark"},
    {"q": "Écris un message pour réserver un taxi pour l'aéroport demain matin. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo"], ["flughafen", "taxi"], ["uhr", "morgen", "heute"], ["bitte", "brauche", "möchte"]], "model": "Guten Tag, ich brauche morgen früh ein Taxi zum Flughafen. Es soll um sechs Uhr kommen. Bitte schreiben Sie mir kurz zurück. Danke, Herr Ali"},
    {"q": "Écris un message à un ami pour lui dire que tu apprends l'allemand. (Hallo, ...)", "min_words": 14, "must": [["hallo", "liebe", "lieber"], ["deutsch", "sprache"], ["lerne", "kurs", "schule"], ["gern", "schwer", "schön", "spaß"]], "model": "Hallo Kofi, ich lerne jetzt Deutsch. Ich habe einen Kurs am Abend. Die Grammatik ist ein bisschen schwer, aber ich lerne gern. Dein Paul"},
    {"q": "Écris un message à un ami pour lui demander à quelle heure commence le film au cinéma. (Hallo, ...)", "min_words": 10, "must": [["hallo", "liebe", "lieber"], ["kino", "film"], ["wann", "uhr", "zeit"]], "model": "Hallo Jonas, gehen wir heute ins Kino? Wann beginnt der Film? Um wie viel Uhr treffen wir uns? Antworte bitte bald, Tina"},
    {"q": "Écris un message pour remercier ta voisine qui t'a offert des fleurs. (Liebe Frau Hahn, ...)", "min_words": 10, "must": [["liebe", "guten tag", "hallo"], ["danke", "dank"], ["blume", "danke"]], "model": "Liebe Frau Hahn, vielen Dank für die schönen Blumen. Ich habe mich sehr gefreut. Sie sind jetzt auf meinem Tisch. Viele Grüße, Anna"},
    {"q": "Écris un message à une amie pour lui demander de s'occuper de ton chat pendant tes vacances. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["katze", "tier"], ["urlaub", "woche", "fahre"], ["bitte", "kannst", "hilf"]], "model": "Hallo Lara, ich fahre nächste Woche in den Urlaub. Kannst du bitte meine Katze füttern? Du bekommst den Schlüssel von mir. Danke, deine Sophie"}
]

SPRECHEN_EXTRA = [
    {"q": "Dis ton prénom et ton âge à voix haute.", "example": "Ich heiße Paul. Ich bin dreißig Jahre alt.", "pattern": "Ich heiße ... Ich bin ... Jahre alt"},
    {"q": "Dis où tu habites et quel est ton métier.", "example": "Ich wohne in Yaoundé. Ich arbeite als Lehrer.", "pattern": "Ich wohne in ... Ich arbeite als ..."},
    {"q": "Salue quelqu'un le matin et demande-lui comment il va (forme polie).", "example": "Guten Morgen! Wie geht es Ihnen?", "pattern": "Guten Morgen Wie geht es Ihnen / Guten Morgen Wie geht's"},
    {"q": "Dis au revoir le soir à un ami.", "example": "Gute Nacht! Bis morgen!", "pattern": "Gute Nacht / Auf Wiedersehen / Tschüss / Bis morgen"},
    {"q": "Remercie quelqu'un qui t'a aidé.", "example": "Vielen Dank! Das ist sehr nett.", "pattern": "Danke / Vielen Dank"},
    {"q": "Excuse-toi parce que tu as fait une erreur.", "example": "Entschuldigung, das tut mir leid.", "pattern": "Entschuldigung / Das tut mir leid"},
    {"q": "Parle de tes frères et soeurs.", "example": "Ich habe einen Bruder und eine Schwester.", "pattern": "Ich habe ... Bruder / Ich habe ... Schwester / Ich habe ... Geschwister / Ich habe keine Geschwister"},
    {"q": "Parle de ton hobby préféré.", "example": "Mein Hobby ist Fußball. Ich spiele gern Fußball.", "pattern": "Mein Hobby ist ... / Ich spiele gern ... / Ich höre gern ... / Ich lese gern ..."},
    {"q": "Dis l'heure qu'il est (par exemple trois heures et demie).", "example": "Es ist halb vier.", "pattern": "Es ist ... Uhr / Es ist halb ... / Es ist viertel ..."},
    {"q": "Demande le prix d'un objet dans un magasin.", "example": "Entschuldigung, was kostet das?", "pattern": "Was kostet das / Wie viel kostet das"},
    {"q": "Commande une boisson au café.", "example": "Ich hätte gern ein Wasser, bitte.", "pattern": "Ich hätte gern ... / Ich möchte ... / Ich nehme ..."},
    {"q": "Demande à un passant où se trouve la gare.", "example": "Entschuldigung, wo ist der Bahnhof?", "pattern": "Wo ist der Bahnhof"},
    {"q": "Dis quel jour nous sommes aujourd'hui et quel jour sera demain.", "example": "Heute ist Montag. Morgen ist Dienstag.", "pattern": "Heute ist ... Morgen ist ..."},
    {"q": "Dis quel temps il fait aujourd'hui.", "example": "Heute ist das Wetter schön. Die Sonne scheint.", "pattern": "Das Wetter ist ... / Es regnet / Es ist ... / Die Sonne scheint / Es schneit"},
    {"q": "Dis quelles langues tu parles.", "example": "Ich spreche Französisch und ein bisschen Deutsch.", "pattern": "Ich spreche ..."},
    {"q": "Compte de un à cinq en allemand.", "example": "Eins, zwei, drei, vier, fünf.", "pattern": "Eins zwei drei vier fünf"},
    {"q": "Dis le nom de deux couleurs en allemand.", "example": "Rot und blau.", "pattern": "rot / blau / grün / gelb / schwarz / weiß / braun"},
    {"q": "Dis ce que tu manges volontiers.", "example": "Ich esse gern Reis und Fisch.", "pattern": "Ich esse gern ... / Ich mag ..."},
    {"q": "Dis à quelle heure tu te lèves le matin.", "example": "Ich stehe um sechs Uhr auf.", "pattern": "Ich stehe um ... Uhr auf"},
    {"q": "Dis ce que tu manges au petit-déjeuner.", "example": "Zum Frühstück esse ich Brot und trinke Tee.", "pattern": "Zum Frühstück ... / Ich frühstücke ... / Ich esse ... zum Frühstück"},
    {"q": "Demande son nom à une personne (forme polie).", "example": "Wie heißen Sie?", "pattern": "Wie heißen Sie / Wie heißt du"},
    {"q": "Demande à une personne d'où elle vient.", "example": "Woher kommen Sie?", "pattern": "Woher kommen Sie / Woher kommst du"},
    {"q": "Dis dans quelle rue tu habites.", "example": "Ich wohne in der Hauptstraße.", "pattern": "Ich wohne in der ... / Meine Adresse ist ..."},
    {"q": "Dis que tu as faim et soif.", "example": "Ich habe Hunger und Durst.", "pattern": "Ich habe Hunger / Ich habe Durst"},
    {"q": "Dis que tu es fatigué et que tu vas au lit.", "example": "Ich bin müde. Ich gehe ins Bett.", "pattern": "Ich bin müde"},
    {"q": "Dis ce que tu veux acheter au marché.", "example": "Ich möchte ein Brot und zwei Äpfel kaufen.", "pattern": "Ich möchte ... / Ich hätte gern ... / Ich brauche ..."},
    {"q": "Dis les quatre premiers mois de l'année.", "example": "Januar, Februar, März, April.", "pattern": "Januar Februar März April"},
    {"q": "Dis en quel mois tu fêtes ton anniversaire.", "example": "Mein Geburtstag ist im Mai.", "pattern": "Mein Geburtstag ist ... / Ich habe im ... Geburtstag"},
    {"q": "Invite un ami à venir à ta fête.", "example": "Kommst du morgen zu meiner Party?", "pattern": "Kommst du ... / Möchtest du ... / Komm ..."},
    {"q": "Réponds poliment à une proposition de café : accepte ou refuse.", "example": "Ja, gern!", "pattern": "Ja gern / Nein danke / Ja bitte"},
    {"q": "Dis que tu n'as pas le temps aujourd'hui.", "example": "Heute habe ich keine Zeit.", "pattern": "Ich habe keine Zeit / Heute habe ich keine Zeit"},
    {"q": "Demande de l'aide poliment.", "example": "Können Sie mir helfen, bitte?", "pattern": "Können Sie mir helfen / Kannst du mir helfen"},
    {"q": "Dis que tu n'as pas compris.", "example": "Ich verstehe das nicht. Noch einmal, bitte.", "pattern": "Ich verstehe nicht / Ich verstehe das nicht / Noch einmal bitte"},
    {"q": "Dis tes horaires de travail.", "example": "Ich arbeite von acht bis siebzehn Uhr.", "pattern": "Ich arbeite von ... bis ..."},
    {"q": "Dis chez le médecin que tu as mal quelque part.", "example": "Ich habe Kopfschmerzen. Ich bin krank.", "pattern": "Ich habe ... / Ich bin krank / Mein ... tut weh"},
    {"q": "Dis comment tu vas au travail.", "example": "Ich fahre mit dem Bus zur Arbeit.", "pattern": "Ich fahre mit dem ... / Ich gehe zu Fuß"},
    {"q": "Dis quel est ton plat préféré.", "example": "Mein Lieblingsessen ist Pizza.", "pattern": "Mein Lieblingsessen ist ..."},
    {"q": "Dis quelle est ta nationalité.", "example": "Ich bin Kameruner. Ich komme aus Kamerun.", "pattern": "Ich bin ... / Ich komme aus ..."},
    {"q": "Dis que tu as un animal de compagnie.", "example": "Ich habe einen Hund. Er heißt Max.", "pattern": "Ich habe einen ... / Ich habe eine ... / Ich habe ein ... / Ich habe keinen ..."},
    {"q": "Demande l'addition au serveur.", "example": "Die Rechnung, bitte.", "pattern": "Die Rechnung bitte / Zahlen bitte / Ich möchte zahlen"}
]

HOREN_QUESTIONS = HOREN_QUESTIONS + HOREN_EXTRA
LESEN_QUESTIONS = LESEN_QUESTIONS + LESEN_EXTRA
SCHREIBEN_QUESTIONS = SCHREIBEN_QUESTIONS + SCHREIBEN_EXTRA
SPRECHEN_QUESTIONS = SPRECHEN_QUESTIONS + SPRECHEN_EXTRA

def _pick_index(bank, sess_key):
    """Tire une question au hasard, différente de la précédente."""
    last = session.get(sess_key + "_last")
    idx = random.randrange(len(bank))
    while len(bank) > 1 and idx == last:
        idx = random.randrange(len(bank))
    session[sess_key + "_last"] = idx
    return idx

def _save_goethe(module, score, total, extra=None):
    data = {"module": module, "score": score, "total": total, "level": "A1"}
    if extra:
        data.update(extra)
    db = get_db()
    db.execute("INSERT INTO goethe_exam(user_id, result_json) VALUES(?,?)",
               (session["user_id"], json.dumps(data, ensure_ascii=False)))
    db.commit()

def _choice_start(bank, sess_key):
    """Nouvelle question à choix : les propositions sont MÉLANGÉES (la bonne n'est plus toujours la 1re)."""
    idx = _pick_index(bank, sess_key)
    q = bank[idx]
    perm = list(range(len(q["opts"])))
    random.shuffle(perm)
    session[sess_key] = {"i": idx, "perm": perm}
    return q, perm

def _choice_state(bank, sess_key):
    st = session.get(sess_key)
    try:
        q = bank[int(st["i"])]
        perm = [int(p) for p in st["perm"]]
        if sorted(perm) != list(range(len(q["opts"]))):
            return None, None
        return q, perm
    except Exception:
        return None, None

def _choice_html(q, perm):
    return ''.join(
        f'<label class="quiz-opt"><input type="radio" name="rep" value="{pos}" required> {pos + 1}. {h(q["opts"][orig])}</label>'
        for pos, orig in enumerate(perm))

@app.route("/goethe")
@login_required
def goethe():
    body = f"""
    <h1>Examen Goethe A1 (Simulateur)</h1>
    <p style="margin-bottom:20px;color:var(--muted);">Cet examen blanc est structuré en 4 modules officiels. Chaque résultat est enregistré dans « Progrès ».</p>

    <div class="grid">
      <div class="card"><h2>1. Hören (Écoute)</h2><p>L'application lit un court dialogue. {len(HOREN_QUESTIONS)} questions.</p><a href="/goethe/horen" class="btn">Commencer</a></div>
      <div class="card"><h2>2. Lesen (Lecture)</h2><p>Lis un court texte et réponds. {len(LESEN_QUESTIONS)} questions.</p><a href="/goethe/lesen" class="btn">Commencer</a></div>
      <div class="card"><h2>3. Schreiben (Écriture)</h2><p>Écris un message simple. {len(SCHREIBEN_QUESTIONS)} sujets.</p><a href="/goethe/schreiben" class="btn">Commencer</a></div>
      <div class="card"><h2>4. Sprechen (Parler)</h2><p>Parle à voix haute, ta prononciation est notée. {len(SPRECHEN_QUESTIONS)} sujets.</p><a href="/goethe/sprechen" class="btn">Commencer</a></div>
    </div>
    """
    return page(layout("Examen Goethe A1", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/horen", methods=["GET","POST"])
@login_required
def goethe_horen():
    if request.method == "GET":
        q, perm = _choice_start(HOREN_QUESTIONS, "ex_horen")
    else:
        q, perm = _choice_state(HOREN_QUESTIONS, "ex_horen")
        if not q:
            return redirect(url_for("goethe_horen"))
        session.pop("ex_horen", None)
        rep = request.form.get("rep", "")
        good_pos = perm.index(int(q["ans"]))
        score = 1 if rep == str(good_pos) else 0
        _save_goethe("Hören", score, 1)
        correct = q["opts"][int(q["ans"])]
        feedback = "✔ Bonne réponse !" if score == 1 else f"✘ Mauvaise réponse. C'était : {h(correct)}"
        body = f"""
        <h1>Hören (Écoute) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if score==1 else 'danger'}">{feedback}</div>
          <p><b>Dialogue :</b> {h(q['audio'])}</p>
          <div style="margin:12px 0;">{say_btn("🔊 Réécouter", "de", "", q['audio'], css="btn ghost")}</div>
          <a href="/goethe/horen" class="btn">Question suivante</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Hören", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Hören (Écoute)</h1>
    <div class="card">
      <p>Écoute attentivement ce dialogue :</p>
      <div style="background:var(--sky-light);padding:16px;border-radius:10px;margin:14px 0;">
        {say_btn("🔊 Écouter le dialogue", "de", "", q['audio'])}
      </div>
      <form method="post">
        <h3>{h(q['q'])}</h3>
        {_choice_html(q, perm)}
        <button class="btn ok" type="submit" style="margin-top:14px">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return page(layout("Hören", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/lesen", methods=["GET","POST"])
@login_required
def goethe_lesen():
    if request.method == "GET":
        q, perm = _choice_start(LESEN_QUESTIONS, "ex_lesen")
    else:
        q, perm = _choice_state(LESEN_QUESTIONS, "ex_lesen")
        if not q:
            return redirect(url_for("goethe_lesen"))
        session.pop("ex_lesen", None)
        rep = request.form.get("rep", "")
        good_pos = perm.index(int(q["ans"]))
        score = 1 if rep == str(good_pos) else 0
        _save_goethe("Lesen", score, 1)
        correct = q["opts"][int(q["ans"])]
        feedback = "✔ Bonne réponse !" if score == 1 else f"✘ Mauvaise réponse. C'était : {h(correct)}"
        body = f"""
        <h1>Lesen (Lecture) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if score==1 else 'danger'}">{feedback}</div>
          <p><b>Texte :</b> {h(q['text'])}</p>
          <a href="/goethe/lesen" class="btn">Question suivante</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Lesen", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Lesen (Lecture)</h1>
    <div class="card">
      <p>Lis ce message :</p>
      <div style="background:var(--sky-light);padding:16px;border-radius:10px;margin:14px 0;font-style:italic;">
        "{h(q['text'])}"
      </div>
      <form method="post">
        <h3>{h(q['q'])}</h3>
        {_choice_html(q, perm)}
        <button class="btn ok" type="submit" style="margin-top:14px">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return page(layout("Lesen", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/schreiben", methods=["GET","POST"])
@login_required
def goethe_schreiben():
    if request.method == "GET":
        idx = _pick_index(SCHREIBEN_QUESTIONS, "ex_schreiben")
        session["ex_schreiben"] = {"i": idx}
        q = SCHREIBEN_QUESTIONS[idx]
    else:
        try:
            q = SCHREIBEN_QUESTIONS[int(session.get("ex_schreiben", {}).get("i"))]
        except Exception:
            return redirect(url_for("goethe_schreiben"))
        session.pop("ex_schreiben", None)
        rep = request.form.get("rep", "").strip()[:1500]
        words = len(rep.split())
        low = rep.lower()
        groups = q.get("must") or []
        hit = [any(alt in low for alt in g) for g in groups]
        got, need = sum(hit), len(groups)
        enough = words >= q["min_words"]
        ok = enough and (need == 0 or got / need >= 0.6)
        _save_goethe("Schreiben", 1 if ok else 0, 1, {"detail": f"{words} mots, {got}/{need} idées"})
        if ok:
            feedback = "✔ Bon travail !"
        elif not enough:
            feedback = f"✘ C'est un peu court : {words} mot(s), vise au moins {q['min_words']} mots."
        else:
            feedback = f"✘ Il manque des éléments demandés par la consigne ({got}/{need} idées trouvées). Relis la consigne."
        model = f'<p style="margin-top:10px;"><b>Modèle de réponse :</b> {h(q["model"])}</p>' if q.get("model") else ""
        body = f"""
        <h1>Schreiben (Écriture) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if ok else 'danger'}">{feedback}</div>
          <p><b>Ta réponse :</b> {h(rep)}</p>
          {model}
          <p style="color:var(--muted);margin-top:10px;">Note : cette correction vérifie la longueur et la présence des idées demandées. Dans un vrai examen, un correcteur humain évalue aussi la grammaire et le vocabulaire.</p>
          <a href="/goethe/schreiben" class="btn">Exercice suivant</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Schreiben", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Schreiben (Écriture)</h1>
    <div class="card">
      <p><b>Consigne :</b> {h(q['q'])}</p>
      <form method="post">
        <label>Ton message :</label>
        <textarea name="rep" rows="4" placeholder="Écris en allemand ici..." required></textarea>
        <button class="btn ok" type="submit">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return page(layout("Schreiben", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/sprechen", methods=["GET","POST"])
@login_required
def goethe_sprechen():
    if request.method == "GET":
        idx = _pick_index(SPRECHEN_QUESTIONS, "ex_sprechen")
        session["ex_sprechen"] = {"i": idx}
        q = SPRECHEN_QUESTIONS[idx]
    else:
        try:
            q = SPRECHEN_QUESTIONS[int(session.get("ex_sprechen", {}).get("i"))]
        except Exception:
            return redirect(url_for("goethe_sprechen"))
        session.pop("ex_sprechen", None)
        heard = request.form.get("heard", "").strip()[:300]
        pattern = q.get("pattern") or ""
        if not heard:
            verdict = ('<div class="flash warning">Aucune réponse enregistrée : exercice non noté. '
                       'Utilise le micro 🎤 (Chrome ou Edge) ou écris ce que tu as dit.</div>')
        elif not pattern:
            verdict = '<div class="flash success">✔ Exercice fait. Cette consigne n\'est pas notée automatiquement : compare avec l\'exemple.</div>'
        else:
            score = _score_pronunciation(pattern, heard)
            ok = score >= 60
            _save_goethe("Sprechen", 1 if ok else 0, 1, {"pct": score})
            cls = "res-ok" if score >= 85 else ("res-mid" if score >= 60 else "res-bad")
            verdict = (f'<div class="flash {"success" if ok else "danger"}">{"✔ Bien joué !" if ok else "✘ À retravailler."}</div>'
                       f'<p>Score de prononciation : <span class="res-score {cls}">{score}%</span></p>'
                       f'<p>Neferti a compris : « {h(heard)} »</p>')
        body = f"""
        <h1>Sprechen (Parler) - Résultat</h1>
        <div class="card">
          {verdict}
          <p style="margin-top:10px;"><b>Exemple :</b> {h(q['example'])}</p>
          <div style="margin:12px 0;">{say_btn("🔊 Écouter l'exemple", "de", "", q['example'], css="btn ghost")}</div>
          <p style="color:var(--muted);margin-top:10px;">Dans un vrai examen Goethe, l'examinateur t'écoute et évalue ta prononciation.</p>
          <a href="/goethe/sprechen" class="btn">Exercice suivant</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Sprechen", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Sprechen (Parler)</h1>
    <div class="card">
      <h2>Consigne</h2>
      <p>{h(q['q'])}</p>
      <div class="sp-box">
        <p style="margin-bottom:10px;"><i>Exemple : {h(q['example'])}</i></p>
        {say_btn("🔊 Écouter l'exemple", "de", "", q['example'])}
      </div>
      <form method="post" id="sp-form">
        <div class="sp-actions">
          <button type="button" class="mic-btn" id="sp-mic" title="Répondre à voix haute">🎤</button>
          <div class="neferti-status" id="sp-status">Clique sur le micro et réponds en allemand (Chrome ou Edge).</div>
        </div>
        <label>Ce que tu as dit (tu peux corriger ou l'écrire toi-même) :</label>
        <input name="heard" id="sp-heard" placeholder="Ta réponse en allemand…" autocomplete="off">
        <button class="btn ok" type="submit">Valider ma réponse</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    <script>
    (function(){{
      var mic = document.getElementById('sp-mic');
      var st = document.getElementById('sp-status');
      var inp = document.getElementById('sp-heard');
      if (!mic) return;
      if (!window.NefertiSupported) {{
        st.textContent = "Reconnaissance vocale indisponible ici : écris ta réponse ci-dessous.";
      }}
      mic.addEventListener('click', function(){{
        if (!window.NefertiSupported) {{ inp.focus(); return; }}
        mic.classList.add('listening');
        st.textContent = "🎙️ Je t'écoute… parle en allemand !";
        window.NefertiStartListening(function(text){{
          inp.value = text;
          st.textContent = "✅ J'ai entendu : « " + text + " ». Clique sur Valider.";
        }}, function(err){{
          mic.classList.remove('listening');
          if (err && err !== 'aborted' && err !== 'no-speech') st.textContent = "⚠️ Erreur micro : " + err + ". Réessaie ou écris ta réponse.";
          else if (err === 'no-speech') st.textContent = "Je n'ai rien entendu. Réessaie.";
        }});
      }});
    }})();
    </script>
    """
    return page(layout("Sprechen", body, {"is_admin": session.get("is_admin")}))

# ---------------------------------------------------------
# ADMIN
# ---------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT id,name,email,is_admin,created_at FROM users ORDER BY id").fetchall()
    lessons_count = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    quiz_count = db.execute("SELECT COUNT(*) FROM goethe_exam").fetchone()[0]
    speak_count = db.execute("SELECT COUNT(*) FROM speak_phrases").fetchone()[0]
    ess_count = db.execute("SELECT COUNT(*) FROM essentials_cards").fetchone()[0]
    nomakk_count = db.execute("SELECT COUNT(*) FROM nomakk_sections").fetchone()[0]
    neferti_scenarios_count = db.execute("SELECT COUNT(*) FROM neferti_scenarios").fetchone()[0]
    neferti_users_count = db.execute("SELECT COUNT(DISTINCT user_id) FROM neferti_history").fetchone()[0]
    neferti_bank_count = db.execute("SELECT COUNT(*) FROM neferti_bank").fetchone()[0]
    vocab_count = db.execute("SELECT COUNT(*) FROM vocab").fetchone()[0]
    dialogues_count = db.execute("SELECT COUNT(*) FROM dialogues").fetchone()[0]
    users_html = "".join(
        f"<tr><td>{u['id']}</td><td>{h(u['name'])}</td><td>{h(u['email'])}</td>"
        f"<td>{'Oui' if u['is_admin'] else 'Non'}</td><td>{h(str(u['created_at']))}</td>"
        f"<td><form method=\"post\" action=\"{url_for('admin_reset_password', uid=u['id'])}\" "
        f"onsubmit=\"return confirm('Générer un nouveau mot de passe temporaire pour cet utilisateur ?')\">"
        f"<button class=\"btn ghost\" type=\"submit\" style=\"padding:6px 12px;font-size:12px\">🔑 Réinitialiser</button></form></td></tr>"
        for u in users
    )
    body = f"""
    <h1>Tableau de bord Admin</h1>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat"><div class="num">{len(users)}</div><div class="lbl">Étudiants</div></div>
      <div class="stat"><div class="num">{lessons_count}</div><div class="lbl">Leçons</div></div>
      <div class="stat"><div class="num">{vocab_count}</div><div class="lbl">Mots de vocabulaire</div></div>
      <div class="stat"><div class="num">{dialogues_count}</div><div class="lbl">Dialogues</div></div>
      <div class="stat"><div class="num">{quiz_count}</div><div class="lbl">Examens Goethe</div></div>
      <div class="stat"><div class="num">{speak_count}</div><div class="lbl">Phrases "Parler"</div></div>
      <div class="stat"><div class="num">{ess_count}</div><div class="lbl">Fiches Essentiels</div></div>
      <div class="stat"><div class="num">{nomakk_count}</div><div class="lbl">Sections des 4 cas</div></div>
      <div class="stat"><div class="num">{neferti_scenarios_count}</div><div class="lbl">Étapes guidées Neferti</div></div>
      <div class="stat"><div class="num">{neferti_bank_count}</div><div class="lbl">Questions Neferti</div></div>
      <div class="stat"><div class="num">{neferti_users_count}</div><div class="lbl">Users Neferti</div></div>
    </div>
    <div class="card">
      <h2>Ajouter une leçon</h2>
      <form method="post" action="{url_for('admin_add_lesson')}">
        <label>Catégorie</label><input name="category" required>
        <label>Allemand (phrase)</label><input name="german" required>
        <label>Français (traduction)</label><input name="french" required>
        <button class="btn" type="submit">Ajouter</button>
      </form>
    </div>
    <div class="card">
      <h2>Utilisateurs</h2>
      <p style="color:var(--muted);font-size:13px;margin-bottom:10px;">« Réinitialiser » génère un mot de passe temporaire (affiché une seule fois) à transmettre à l'étudiant, qui pourra le changer dans « Mon compte ».</p>
      <div style="overflow-x:auto;">
      <table><thead><tr><th>ID</th><th>Nom</th><th>Email</th><th>Admin</th><th>Inscrit le</th><th>Mot de passe</th></tr></thead>
      <tbody>{users_html}</tbody></table>
      </div>
    </div>
    """
    return page(layout("Admin", body, {"is_admin": True}))

@app.route("/admin/add_lesson", methods=["POST"])
@admin_required
def admin_add_lesson():
    cat = request.form.get("category","").strip()
    de = request.form.get("german","").strip()
    fr = request.form.get("french","").strip()
    if cat and de and fr:
        db = get_db()
        nxt = db.execute("SELECT COALESCE(MAX(order_index), -1) + 1 FROM lessons").fetchone()[0]
        db.execute("INSERT INTO lessons(category,title,french,german,order_index) VALUES(?,?,?,?,?)",
                   (cat,de,fr,de,nxt))
        db.commit()
        flash("Leçon ajoutée.","success")
    else:
        flash("Champs manquants.","danger")
    return redirect(url_for("admin"))

@app.route("/admin/reset_password/<int:uid>", methods=["POST"])
@admin_required
def admin_reset_password(uid):
    db = get_db()
    u = db.execute("SELECT id, name, email FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        flash("Utilisateur introuvable.","danger")
        return redirect(url_for("admin"))
    temp = secrets.token_urlsafe(8) + "Aa1"
    db.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(temp), uid))
    db.commit()
    flash(f"Mot de passe temporaire pour {u['email']} : {temp} (note-le maintenant, il ne sera plus affiché).","success")
    return redirect(url_for("admin"))

# ---------------------------------------------------------
# MON COMPTE (changer le mot de passe, supprimer le compte)
# ---------------------------------------------------------
@app.route("/compte")
@login_required
def compte():
    db = get_db()
    u = db.execute("SELECT name, email, created_at FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not u:
        session.clear()
        return redirect(url_for("login"))
    if session.get("is_admin"):
        delete_card = """
        <div class="card"><h2>Supprimer mon compte</h2>
        <p style="color:var(--muted);">Le compte administrateur ne peut pas être supprimé depuis cette page.</p></div>"""
    else:
        delete_card = f"""
        <div class="card danger-zone">
          <h2>Supprimer mon compte</h2>
          <p style="color:var(--muted);margin-bottom:10px;">Efface définitivement ton compte, ta progression, tes résultats d'examen et la mémoire de Neferti. Cette action est irréversible.</p>
          <form method="post" action="{url_for('compte_supprimer')}" onsubmit="return confirm('Supprimer définitivement ton compte ?')">
            <label>Mot de passe</label><input name="password" type="password" required autocomplete="current-password">
            <button class="btn danger" type="submit">Supprimer mon compte</button>
          </form>
        </div>"""
    body = f"""
    <h1>Mon compte 👤</h1>
    <div class="card">
      <p><b>Nom :</b> {h(u['name'])}</p>
      <p><b>Email :</b> {h(u['email'])}</p>
      <p><b>Inscrit le :</b> {h(str(u['created_at']))}</p>
    </div>
    <div class="card">
      <h2>Changer mon mot de passe</h2>
      <form method="post" action="{url_for('compte_mot_de_passe')}">
        <label>Mot de passe actuel</label><input name="current" type="password" required autocomplete="current-password">
        <label>Nouveau mot de passe</label><input name="new" type="password" required autocomplete="new-password" placeholder="Min. 8 car., Maj., min., chiffre">
        <button class="btn" type="submit">Changer</button>
      </form>
    </div>
    {delete_card}
    """
    return page(layout("Mon compte", body, {"is_admin": session.get("is_admin")}))

@app.route("/compte/mot-de-passe", methods=["POST"])
@login_required
def compte_mot_de_passe():
    db = get_db()
    uid = session["user_id"]
    k_ip, k_id = _login_keys("pw%d" % uid)
    if _login_blocked(db, k_ip, k_id):
        flash("Trop de tentatives. Réessaie dans quelques minutes.","danger")
        return redirect(url_for("compte"))
    row = db.execute("SELECT password FROM users WHERE id=?", (uid,)).fetchone()
    current = request.form.get("current","")
    new = request.form.get("new","")
    if not row or not check_pwd(row["password"], current):
        _login_fail(db, k_ip, k_id)
        flash("Mot de passe actuel incorrect.","danger")
    elif not validate_password(new):
        flash("Nouveau mot de passe trop faible. Il faut au moins 8 caractères, une majuscule, une minuscule et un chiffre.","danger")
    else:
        db.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(new), uid))
        db.commit()
        flash("Mot de passe modifié.","success")
    return redirect(url_for("compte"))

@app.route("/compte/supprimer", methods=["POST"])
@login_required
def compte_supprimer():
    if session.get("is_admin"):
        flash("Le compte administrateur ne peut pas être supprimé.","danger")
        return redirect(url_for("compte"))
    db = get_db()
    uid = session["user_id"]
    k_ip, k_id = _login_keys("pw%d" % uid)
    if _login_blocked(db, k_ip, k_id):
        flash("Trop de tentatives. Réessaie dans quelques minutes.","danger")
        return redirect(url_for("compte"))
    row = db.execute("SELECT password FROM users WHERE id=?", (uid,)).fetchone()
    if not row or not check_pwd(row["password"], request.form.get("password","")):
        _login_fail(db, k_ip, k_id)
        flash("Mot de passe incorrect : compte non supprimé.","danger")
        return redirect(url_for("compte"))
    for table in ("progress", "goethe_exam", "neferti_memory", "neferti_history", "neferti_asked"):
        db.execute(f"DELETE FROM {table} WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    session.clear()
    flash("Ton compte et toutes tes données ont été supprimés.","success")
    return redirect(url_for("index"))

# ---------------------------------------------------------
# LANCEMENT
# ---------------------------------------------------------
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("NATHO_DEBUG") == "1", host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))

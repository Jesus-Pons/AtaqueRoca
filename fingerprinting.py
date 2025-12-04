import random
import tkinter as tk
from tkinter import messagebox, ttk


class ROCAEngine:
    def __init__(self):
        self.PRIMES = [
            3,
            5,
            7,
            11,
            13,
            17,
            19,
            23,
            29,
            31,
            37,
            41,
            43,
            47,
            53,
            59,
            61,
            67,
            71,
            73,
            79,
            83,
            89,
            97,
            101,
            103,
            107,
            109,
            113,
            127,
            131,
            137,
            139,
            149,
            151,
            157,
            163,
            167,
        ]
        self.GENERATOR = 65537
        self.M = 1
        for p in self.PRIMES:
            self.M *= p

        self.subgroups = self._precompute_subgroups()

    def _precompute_subgroups(self):
        """Precalcula los residuos válidos para la detección."""
        subgroups = {}
        for p in self.PRIMES:
            allowed = set()
            val = 1
            while val not in allowed:
                allowed.add(val)
                val = (val * self.GENERATOR) % p
            subgroups[p] = allowed
        return subgroups

    def check_vulnerability(self, modulus_int):
        """Devuelve (EsVulnerable, MensajeExplicativo)"""
        log = []
        for p in self.PRIMES:
            residue = modulus_int % p
            if residue not in self.subgroups[p]:
                return (
                    False,
                    f"Fallo en primo {p}: El residuo {residue} no pertenece al subgrupo de Infineon.",
                )
        return True, "El módulo cumple el patrón ROCA para todos los primos testados."

    def get_stats(self, bit_length):
        if bit_length <= 512:
            return "2 horas", "< 0.10 $"
        elif bit_length <= 1024:
            return "97 días (Cluster)", "~ 80 $"
        elif bit_length <= 2048:
            return "140 años", "~ 40.000 $"
        elif bit_length <= 4096:
            return "Impráctico", "Millones $"
        else:
            return "?", "?"

    def generate_vulnerable_key(self):
        """Genera N = k*M + 65537^a mod M"""
        a = random.randint(1, 1000)
        residue = pow(self.GENERATOR, a, self.M)
        k = random.getrandbits(800)
        return k * self.M + residue

    def is_prime_miller_rabin(self, n, k=40):
        """Test probabilístico de primalidad (Miller-Rabin)."""
        if n == 2:
            return True
        if n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def get_random_prime(self, n_bits):
        """Genera un primo aleatorio real."""
        while True:
            candidate = random.getrandbits(n_bits)
            if candidate % 2 == 0:
                candidate += 1
            if candidate % 3 == 0 or candidate % 5 == 0:
                continue
            if self.is_prime_miller_rabin(candidate, k=5):
                return candidate

    def generate_safe_key(self):
        """Genera un módulo RSA estándar (N = p*q) sin estructura Infineon."""
        p = self.get_random_prime(512)
        q = self.get_random_prime(512)
        n = p * q
        return n


class ROCAApp:
    def __init__(self, root):
        self.engine = ROCAEngine()
        self.root = root
        self.root.title("Trabajo G-5: ROCA Analyzer Tool")
        self.root.geometry("850x650")
        self.root.configure(bg="#f0f2f5")
        tk.Label(
            root,
            text="Herramienta de Análisis ROCA",
            font=("Segoe UI", 20, "bold"),
            bg="#f0f2f5",
            fg="#333",
        ).pack(pady=20)
        tk.Label(
            root,
            text="(CVE-2017-15361 - Infineon RSA Library)",
            font=("Segoe UI", 10),
            bg="#f0f2f5",
            fg="#666",
        ).pack()

        lbl_in = tk.Label(
            root, text="Módulo RSA (N):", bg="#f0f2f5", font=("Arial", 11, "bold")
        )
        lbl_in.pack(anchor="w", padx=40, pady=(20, 0))
        self.text_input = tk.Text(
            root,
            height=8,
            width=90,
            borderwidth=1,
            relief="solid",
            font=("Consolas", 9),
            fg="#333",
        )
        self.text_input.pack(pady=5, padx=40)
        frame_btns = tk.Frame(root, bg="#f0f2f5")
        frame_btns.pack(pady=20)

        tk.Button(
            frame_btns,
            text="🔍 ANALIZAR",
            command=self.analyze,
            bg="#007bff",
            fg="white",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=8,
            bd=0,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            frame_btns,
            text="Limpiar",
            command=self.clear,
            bg="white",
            fg="#333",
            font=("Arial", 10),
            padx=15,
            pady=8,
            bd=1,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=10)

        ttk.Separator(frame_btns, orient="vertical").pack(
            side=tk.LEFT, fill="y", padx=30
        )

        tk.Button(
            frame_btns,
            text="🛡️ Generar Seguro",
            command=self.gen_safe,
            bg="#28a745",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=15,
            pady=8,
            bd=0,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            frame_btns,
            text="⚠️ Generar Vulnerable",
            command=self.gen_vuln,
            bg="#dc3545",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=15,
            pady=8,
            bd=0,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=5)

        self.frame_res = tk.Frame(root, bg="white", borderwidth=1, relief="solid")
        self.frame_res.pack(fill="both", expand=True, padx=40, pady=20)
        self.lbl_status = tk.Label(
            self.frame_res,
            text="Sistema listo. Esperando clave...",
            font=("Segoe UI", 16, "bold"),
            bg="white",
            fg="#aaa",
        )
        self.lbl_status.pack(pady=25)
        self.lbl_detail = tk.Label(
            self.frame_res, text="", font=("Consolas", 10), bg="white", justify=tk.LEFT
        )
        self.lbl_detail.pack(pady=5)

    def clear(self):
        self.text_input.delete("1.0", tk.END)
        self.frame_res.config(bg="white")
        self.lbl_status.config(text="Sistema listo.", bg="white", fg="#aaa")
        self.lbl_detail.config(text="", bg="white")

    def gen_safe(self):
        """Genera clave RSA estándar aleatoria"""
        self.clear()
        try:
            safe_key = self.engine.generate_safe_key()
            self.text_input.insert("1.0", str(safe_key))
            messagebox.showinfo(
                "Generado",
                "Se ha generado un Módulo RSA Estándar (Aleatorio).\n\nN = p * q\n(Donde p y q son primos aleatorios sin estructura Infineon).",
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def gen_vuln(self):
        """Genera clave ROCA"""
        self.clear()
        try:
            vuln_key = self.engine.generate_vulnerable_key()
            self.text_input.insert("1.0", str(vuln_key))
            messagebox.showwarning(
                "Generado",
                "⚠️ Se ha generado un Módulo con estructura ROCA.\n\nEste número cumple la condición matemática defectuosa.",
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def analyze(self):
        content = self.text_input.get("1.0", tk.END).strip()
        if not content:
            return

        clean = "".join(filter(lambda x: x in "0123456789abcdefABCDEF", content))

        try:
            is_hex = any(
                c in "abcdefABCDEF" for c in clean
            ) or content.strip().startswith("00")
            modulus = int(clean, 16) if is_hex else int(clean)
            is_vuln, reason = self.engine.check_vulnerability(modulus)
            bit_len = modulus.bit_length()
            time_est, cost_est = self.engine.get_stats(bit_len)

            self.show_results(is_vuln, bit_len, reason, time_est, cost_est)

        except ValueError:
            messagebox.showerror("Error", "Formato de número inválido.")

    def show_results(self, is_vuln, bits, reason, time, cost):
        if is_vuln:
            color = "#ffe6e6"
            fg = "#b30000"
            status = "❌ VULNERABLE DETECTADO"
            info = (
                f" DETALLE DEL ANÁLISIS:\n"
                f" ---------------------\n"
                f" • Tamaño: {bits} bits\n"
                f" • Origen: Librería Infineon RSALib (2012-2017)\n"
                f" • Evidencia: Cumple la propiedad de subgrupo discreto <65537>\n"
                f"              para el conjunto de primos de prueba.\n\n"
                f" IMPACTO (Ataque Coppersmith):\n"
                f" • Tiempo CPU: {time}\n"
                f" • Coste AWS:  {cost}"
            )
        else:
            color = "#e6fffa"
            fg = "#006644"
            status = "✅ SEGURO / ESTÁNDAR"
            info = (
                f" DETALLE DEL ANÁLISIS:\n"
                f" ---------------------\n"
                f" • Tamaño: {bits} bits\n"
                f" • Origen: Probablemente OpenSSL, /dev/urandom o Hardware seguro.\n"
                f" • Análisis: No se detecta la huella digital de Infineon.\n\n"
                f" • Razón Matemática:\n"
                f"   {reason}"
            )

        self.frame_res.config(bg=color)
        self.lbl_status.config(text=status, bg=color, fg=fg)
        self.lbl_detail.config(text=info, bg=color)


if __name__ == "__main__":
    root = tk.Tk()
    app = ROCAApp(root)
    root.mainloop()

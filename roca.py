import random
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, ttk

# ==============================================================================
# CONFIGURACIÓN MATEMÁTICA DEL ATAQUE
# ==============================================================================


class MiniROCA:
    def __init__(self):
        # Usamos un conjunto de primos para construir un M (Primorial)
        # Esto simula un entorno Infineon a escala reducida para la demo.
        self.PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
        self.GENERATOR = 65537

        # Calculamos M (El producto de los primos)
        self.M = 1
        for p in self.PRIMES:
            self.M *= p

        # Precalculamos el orden del generador en este grupo para saber cuánto buscar
        # (Simplificación para la demo)
        self.group_limit = 10000

    # --- 1. GENERADOR DE LA VÍCTIMA ---
    def generate_vulnerable_keypair(self):
        """Genera una clave privada (p, q) y pública (N) con estructura Infineon"""
        # Generamos p con la fórmula: p = k * M + (65537^a mod M)
        a_p = random.randint(1, self.group_limit)  # Exponente secreto
        k_p = random.randint(1, 100)  # Multiplicador aleatorio

        # Residuo específico de Infineon
        residue_p = pow(self.GENERATOR, a_p, self.M)
        p = k_p * self.M + residue_p

        # Hacemos lo mismo para q
        a_q = random.randint(1, self.group_limit)
        k_q = random.randint(1, 100)
        residue_q = pow(self.GENERATOR, a_q, self.M)
        q = k_q * self.M + residue_q

        # Calculamos N
        N = p * q
        return N, p, q, a_p, a_q

    # --- 2. EL ATACANTE (CRACKER) ---
    def attack(self, N, progress_callback=None):
        """
        Intenta factorizar N sabiendo que p tiene la forma k*M + 65537^a
        En lugar de buscar en todo el espacio (Fuerza bruta imposible),
        buscamos solo en el subgrupo generado por 65537.
        """
        start_time = time.time()
        attempts = 0

        current_residue = 1

        for a in range(1, self.group_limit * 2):
            attempts += 1

            current_residue = (current_residue * self.GENERATOR) % self.M

            for k_guess in range(1, 150):  # Asumimos k pequeño para la demo
                p_candidate = k_guess * self.M + current_residue

                if p_candidate > 1 and N % p_candidate == 0:
                    end_time = time.time()
                    return (
                        p_candidate,
                        N // p_candidate,
                        end_time - start_time,
                        attempts,
                        a,
                        k_guess,
                    )

            if progress_callback and a % 100 == 0:
                progress_callback(a)

        return None, None, 0, attempts, None, None


class RocaApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Demostración del Ataque ROCA")
        self.geometry("800x650")

        self.roca = MiniROCA()
        self.N = None
        self.real_p = None
        self.real_q = None
        self.real_a = None

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)

        gen_frame = ttk.LabelFrame(
            main_frame, text="1. Generación de Clave Vulnerable", padding="10"
        )
        gen_frame.pack(fill="x", pady=5)

        self.generate_button = ttk.Button(
            gen_frame, text="Generar Clave", command=self.generate_key_gui
        )
        self.generate_button.pack(pady=5)

        self.key_info_label = ttk.Label(
            gen_frame, text="Esperando generación de clave..."
        )
        self.key_info_label.pack(pady=5)

        attack_frame = ttk.LabelFrame(
            main_frame, text="2. Criptoanálisis (Ataque)", padding="10"
        )
        attack_frame.pack(fill="x", pady=5)

        self.attack_button = ttk.Button(
            attack_frame,
            text="Lanzar Ataque",
            command=self.start_attack_thread,
            state="disabled",
        )
        self.attack_button.pack(pady=5)

        self.progress_label = ttk.Label(attack_frame, text="Estado: Inactivo")
        self.progress_label.pack(pady=5)

        results_frame = ttk.LabelFrame(main_frame, text="3. Resultados", padding="10")
        results_frame.pack(fill="both", expand=True, pady=5)

        self.results_text = scrolledtext.ScrolledText(
            results_frame, height=15, wrap=tk.WORD, state="disabled"
        )
        self.results_text.pack(fill="both", expand=True)

    def log_result(self, message):
        self.results_text.config(state="normal")
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.config(state="disabled")
        self.results_text.see(tk.END)

    def generate_key_gui(self):
        self.results_text.config(state="normal")
        self.results_text.delete("1.0", tk.END)

        self.log_result("--- GENERANDO CLAVE VULNERABLE ---")
        self.log_result(
            f"[*] Generando primos basados en M (approx {self.roca.M.bit_length()} bits)..."
        )

        self.N, self.real_p, self.real_q, self.real_a, real_b = (
            self.roca.generate_vulnerable_keypair()
        )

        info = (
            f"Clave Pública (N) generada: {str(self.N)[:40]}... ({self.N.bit_length()} bits)\n"
            f"  - Primo 'p' secreto (para verificación): {str(self.real_p)[:20]}...\n"
            f"  - Exponente secreto 'a' usado para 'p': {self.real_a}"
        )
        self.key_info_label.config(text=info)
        self.log_result("Clave generada con éxito.")
        self.log_result("-" * 60)
        self.attack_button.config(state="normal")
        self.progress_label.config(text="Listo para atacar.")

    def update_progress(self, a_value):
        self.progress_label.config(text=f"Buscando... Probando exponente a = {a_value}")

    def start_attack_thread(self):
        self.attack_button.config(state="disabled")
        self.generate_button.config(state="disabled")
        self.log_result("\n[ATAQUE INICIADO]")
        self.log_result(f"Objetivo N: {str(self.N)[:40]}...")
        self.log_result("Buscando exponente 'a' en el subgrupo vulnerable...")

        thread = threading.Thread(target=self.run_attack, daemon=True)
        thread.start()

    def run_attack(self):
        found_p, found_q, duration, tries, found_a, found_k = self.roca.attack(
            self.N, self.update_progress
        )

        self.after(
            0,
            self.show_attack_results,
            found_p,
            found_q,
            duration,
            tries,
            found_a,
            found_k,
        )

    def show_attack_results(self, found_p, found_q, duration, tries, found_a, found_k):
        self.progress_label.config(text="Ataque finalizado.")
        self.log_result("\n" + "=" * 60)
        self.log_result("RESULTADO DEL CRIPTOANÁLISIS")
        self.log_result("=" * 60)

        if found_p:
            self.log_result(f"[¡ÉXITO!] Factor encontrado con a={found_a}, k={found_k}")
            self.log_result(f"Tiempo de ataque: {duration:.4f} segundos")
            self.log_result(f"Intentos realizados: {tries}")
            self.log_result(f"Factor P recuperado: {found_p}")
            self.log_result(f"Factor Q recuperado: {found_q}")

            if found_p == self.real_p or found_p == self.real_q:
                self.log_result("\nVERIFICACIÓN: ✅ La clave privada es CORRECTA.")
            else:
                self.log_result("\nVERIFICACIÓN: ❌ Algo falló en la lógica.")

            self.log_result("\nCONCLUSIÓN:")
            self.log_result(
                "Una clave aleatoria de este tamaño tardaría eones en romperse."
            )
            self.log_result(
                "Gracias a la estructura predecible, el ataque fue exitoso en segundos."
            )

        else:
            self.log_result(
                "[FALLO] No se encontró la clave en el espacio de búsqueda limitado."
            )

        self.generate_button.config(state="normal")


if __name__ == "__main__":
    app = RocaApp()
    app.mainloop()

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import subprocess
import threading
import sys

# Variables globales
process = None  # Pour stocker le processus en cours d'exécution
stop_requested = False  # Variable de contrôle pour arrêter proprement le thread

# Créer la fenêtre principale
root = tk.Tk()
root.title("Interface gg2.py")
root.geometry("800x700")

# Zone de texte défilante pour afficher les sorties
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=15)
output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Tableau Treeview pour les adresses IP bloquées
table_frame = tk.Frame(root)
table_frame.pack(pady=10)

table_label = tk.Label(table_frame, text="Adresses IP bloquées :", font=('Arial', 12, 'bold'))
table_label.pack()

table = ttk.Treeview(table_frame, columns=("Adresse IP", "Temps restant (s)"), show="headings")
table.heading("Adresse IP", text="Adresse IP")
table.heading("Temps restant (s)", text="Temps restant (s)")
table.column("Adresse IP", width=200)
table.column("Temps restant (s)", width=150)
table.pack(pady=5)

# Barre d'état
status_label = tk.Label(root, text="Statut : Prêt", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

def update_status(status):
    status_label.config(text=f"Statut : {status}")
    status_label.update()

# Fonction pour exécuter gg2.py
def run_script():
    global process, stop_requested
    stop_requested = False  # Réinitialiser la demande d'arrêt
    
    output_text.delete(1.0, tk.END)  # Efface le contenu précédent
    table.delete(*table.get_children())  # Efface les anciennes entrées dans le tableau
    update_status("Exécution du script en cours...")
    output_text.insert(tk.END, "Exécution du script...\n")
    output_text.see(tk.END)
    
    # Récupérer le temps de blocage
    block_duration = block_duration_entry.get()
    if not block_duration.isdigit() or int(block_duration) <= 0:
        messagebox.showerror("Erreur", "Veuillez entrer un temps de blocage valide (nombre entier positif).")
        update_status("Erreur : Temps de blocage invalide.")
        return
    
    try:
        def execute():
            global process, stop_requested
            process = subprocess.Popen(
                [sys.executable, '-u', 'C:/Users/ECC/Desktop/PROJET_SECURITE/sansNetshVS.py', '--block-duration', block_duration],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                for line in iter(process.stdout.readline, ''):
                    if stop_requested or process.poll() is not None:
                        break
                    if "Tableau des adresses bloquées" in line:
                        continue  # Ignore les lignes d'entête du tableau
                    if "|" in line and "." in line:  # Détecte une ligne d'adresse IP
                        parts = line.split('|')
                        if len(parts) >= 3:
                            ip = parts[1].strip()
                            time_left = parts[2].strip()
                            # Met à jour ou ajoute l'adresse IP dans le tableau
                            update_table(ip, time_left)
                    else:
                        output_text.insert(tk.END, line)
                        output_text.see(tk.END)
                
            except Exception as e:
                output_text.insert(tk.END, f"Exception: {e}\n")
                output_text.see(tk.END)
            
            finally:
                process.stdout.close()
                process.stderr.close()
                process.wait()
                if stop_requested:
                    update_status("Script arrêté par l'utilisateur.")
                    output_text.insert(tk.END, "Script arrêté manuellement.\n")
                else:
                    update_status("Exécution terminée.")
        
        threading.Thread(target=execute, daemon=True).start()
    
    except Exception as e:
        output_text.insert(tk.END, f"Exception: {e}\n")
        output_text.see(tk.END)
        update_status("Erreur lors de l'exécution.")

# Fonction pour mettre à jour le tableau des IP bloquées
def update_table(ip, time_left):
    for item in table.get_children():
        if table.item(item, 'values')[0] == ip:
            table.item(item, values=(ip, time_left))  # Met à jour le temps restant
            return
    # Ajoute une nouvelle IP si elle n'existe pas
    table.insert('', 'end', values=(ip, time_left))

# Fonction pour arrêter gg2.py
def stop_script():
    global process, stop_requested
    if process:
        try:
            stop_requested = True  # Signale au thread d'arrêter
            process.terminate()  # Termine le processus
            process = None
            update_status("Script arrêté par l'utilisateur.")
            output_text.insert(tk.END, "Script arrêté manuellement.\n")
            output_text.see(tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'arrêter le script : {e}")
            update_status("Erreur lors de l'arrêt du script.")
    else:
        messagebox.showinfo("Information", "Aucun script en cours d'exécution.")

# Champ pour modifier le temps de blocage
block_duration_label = tk.Label(root, text="Temps de blocage (en secondes) :", font=('Arial', 12))
block_duration_label.pack(pady=(10, 0))

block_duration_entry = tk.Entry(root, font=('Arial', 12))
block_duration_entry.insert(0, "60")  # Valeur par défaut
block_duration_entry.pack(pady=(0, 10))

# Boutons d'exécution et d'arrêt
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

execute_button = tk.Button(button_frame, text="Exécuter", command=run_script, bg='green', fg='white', font=('Arial', 12, 'bold'))
execute_button.grid(row=0, column=0, padx=5)

stop_button = tk.Button(button_frame, text="Arrêter", command=stop_script, bg='red', fg='white', font=('Arial', 12, 'bold'))
stop_button.grid(row=0, column=1, padx=5)

# Démarrer l'interface
root.mainloop()
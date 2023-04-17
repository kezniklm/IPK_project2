import os

folder = "."

for filename in os.listdir(folder):
    if filename.endswith(".src"):
        src_file = os.path.join(folder, filename)
        out_file = os.path.join(folder, filename[:-4] + ".out")

        if os.path.exists(out_file):
            with open(src_file) as f1, open(out_file) as f2:
                # Prečíta riadok a vymaže whitespaces
                content1 = f1.read().replace(" ", "").lower()
                content2 = f2.read().replace(" ", "").lower()

                if content1 == content2:
                    print(f"{filename}: Files are identical")
                else:
                    lines1 = content1.splitlines()
                    lines2 = content2.splitlines()

                    # Skontroluje, či má súbor aspon jeden riadok
                    if len(lines2) > 1:
                        # Preskočí prvý riadok v rámci .ou súborus
                        start_index = 1
                        for line_num, (line1, line2) in enumerate(zip(lines1, lines2[start_index:])):
                            if line1 != line2:
                                print(f"{filename}: Line {line_num + start_index + 1} differs:")
                                print(f"{filename}.src: {line1}")
                                print(f"{filename}.out: {line2}")
                                print()
                    else:
                        # V prípade, že má súbor iba jeden riadok -> chyba
                        print(f"{filename}: Invalid .out file")
        else:
            print(f"{filename}: Missing .out file")
    elif filename.endswith(".out"):
        # .out súbory sú ignorované
        pass
    else:
        # ostatné súbory sú ignorované
        pass

"""
Command Line Interface for Shellock.

This module provides the CLI using Click framework with Rich UI for
secure encryption and decryption of configuration files.
"""

import base64
import getpass
import os
import secrets
import sys
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .api import (
    decrypt_file,
    decrypt_file_key,
    decrypt_file_private,
    encrypt_file,
    encrypt_file_key,
    encrypt_file_public,
)
from .crypto import KEY_SIZE, generate_keypair
from .exceptions import AuthenticationError, InvalidFileFormatError

# Rich console for formatted output
console = Console()


@click.group()
@click.version_option(package_name="shellock")
def cli() -> None:
    """Shellock - Secure encryption for configuration files.

    Shellock provides strong encryption for your configuration files using
    AES-256-GCM with Argon2id key derivation. It supports passphrase-based,
    symmetric key-based, and asymmetric (public/private key) encryption.

    \b
    Examples:
        # Encrypt with passphrase
        shellock encrypt config.env --out config.env.enc

        # Decrypt with passphrase
        shellock decrypt config.env.enc --out config.env

        # Generate a symmetric key
        shellock generate-key --type symmetric --out secret.key

        # Encrypt with symmetric key
        shellock encrypt-key config.env --key secret.key --out config.env.enc

        # Generate an asymmetric keypair
        shellock generate-key --type asymmetric --out private.pem

        # Encrypt with public key
        shellock encrypt-public config.env --key public.pem --out config.env.enc
    """
    pass


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file path for the encrypted data.",
)
@click.option(
    "--passphrase",
    "-p",
    help="Passphrase for encryption. If not provided, will prompt securely.",
)
def encrypt(input_file: str, out: str, passphrase: Optional[str]) -> None:
    """Encrypt a file with a passphrase.

    Encrypts INPUT_FILE using AES-256-GCM with Argon2id key derivation
    and writes the encrypted output to the specified path.

    \b
    Examples:
        shellock encrypt config.env --out config.env.enc
        shellock encrypt config.env -o config.env.enc -p "my secret"
    """
    if not passphrase:
        passphrase = getpass.getpass("Passphrase: ")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Encrypting...", total=None)
            encrypt_file(input_file, out, passphrase)

        console.print(f"[green]✓[/green] Encrypted: {input_file} → {out}")
        sys.exit(0)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Encryption failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file path for the decrypted data.",
)
@click.option(
    "--passphrase",
    "-p",
    help="Passphrase for decryption. If not provided, will prompt securely.",
)
def decrypt(input_file: str, out: str, passphrase: Optional[str]) -> None:
    """Decrypt a file with a passphrase.

    Decrypts INPUT_FILE using AES-256-GCM with Argon2id key derivation
    and writes the decrypted output to the specified path.

    \b
    Examples:
        shellock decrypt config.env.enc --out config.env
        shellock decrypt config.env.enc -o config.env -p "my secret"
    """
    if not passphrase:
        passphrase = getpass.getpass("Passphrase: ")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Decrypting...", total=None)
            decrypt_file(input_file, out, passphrase)

        console.print(f"[green]✓[/green] Decrypted: {input_file} → {out}")
        sys.exit(0)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except InvalidFileFormatError:
        console.print("[red]Error:[/red] Invalid file format")
        sys.exit(1)
    except AuthenticationError:
        console.print("[red]Error:[/red] Authentication failed")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Decryption failed: {e}")
        sys.exit(1)


@cli.command("generate-key")
@click.option(
    "--type",
    "key_type",
    type=click.Choice(["symmetric", "asymmetric"]),
    default="symmetric",
    help="Type of key to generate: symmetric (AES-256) or asymmetric (X25519).",
)
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file path for the generated key.",
)
@click.confirmation_option(prompt="Generate a new encryption key?")
def generate_key(key_type: str, out: str) -> None:
    """Generate a random encryption key.

    Generates either a symmetric key (32 random bytes, base64-encoded)
    or an asymmetric X25519 keypair (private key in PEM format).

    \b
    Examples:
        shellock generate-key --type symmetric --out secret.key
        shellock generate-key --type asymmetric --out private.pem
    """
    try:
        if key_type == "symmetric":
            # Generate 32 random bytes for symmetric key
            key = secrets.token_bytes(KEY_SIZE)
            key_b64 = base64.b64encode(key).decode()

            with open(out, "w") as f:
                f.write(key_b64)

            # Set secure permissions (600)
            os.chmod(out, 0o600)

            console.print(f"[green]✓[/green] Symmetric key generated: {out}")
        else:
            # Generate X25519 keypair
            private_key_pem, public_key_pem = generate_keypair()

            # Write private key to file
            with open(out, "wb") as f:
                f.write(private_key_pem)

            # Set secure permissions (600)
            os.chmod(out, 0o600)

            console.print("[green]✓[/green] Keypair generated!")
            console.print(f"Private key: {out}")
            console.print("\n[yellow]Public key (safe to share):[/yellow]")
            console.print(public_key_pem.decode())

        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error:[/red] Key generation failed: {e}")
        sys.exit(1)


@cli.command("encrypt-public")
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--key",
    "-k",
    required=True,
    type=click.Path(exists=True),
    help="Path to the public key file (PEM format).",
)
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file path for the encrypted data.",
)
def encrypt_public(input_file: str, key: str, out: str) -> None:
    """Encrypt a file with a public key.

    Encrypts INPUT_FILE using hybrid encryption (X25519 + AES-256-GCM)
    with the specified public key.

    \b
    Examples:
        shellock encrypt-public config.env --key public.pem --out config.env.enc
    """
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Encrypting with public key...", total=None)
            encrypt_file_public(input_file, out, key)

        console.print(f"[green]✓[/green] Encrypted: {input_file} → {out}")
        sys.exit(0)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except InvalidFileFormatError as e:
        console.print(f"[red]Error:[/red] Invalid key format: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Encryption failed: {e}")
        sys.exit(1)


@cli.command("decrypt-private")
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--key",
    "-k",
    required=True,
    type=click.Path(exists=True),
    help="Path to the private key file (PEM format).",
)
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file path for the decrypted data.",
)
@click.option(
    "--passphrase",
    "-p",
    help="Private key passphrase. If key is encrypted and not provided, will prompt.",
)
def decrypt_private(
    input_file: str, key: str, out: str, passphrase: Optional[str]
) -> None:
    """Decrypt a file with a private key.

    Decrypts INPUT_FILE using hybrid decryption (X25519 + AES-256-GCM)
    with the specified private key.

    \b
    Examples:
        shellock decrypt-private config.env.enc --key private.pem --out config.env
    """
    # Prompt for passphrase if not provided (for encrypted private keys)
    if passphrase is None:
        passphrase_input = getpass.getpass(
            "Private key passphrase (leave empty if none): "
        )
        passphrase = passphrase_input if passphrase_input else None

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Decrypting with private key...", total=None)
            decrypt_file_private(input_file, out, key, passphrase)

        console.print(f"[green]✓[/green] Decrypted: {input_file} → {out}")
        sys.exit(0)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except InvalidFileFormatError:
        console.print("[red]Error:[/red] Invalid file format")
        sys.exit(1)
    except AuthenticationError:
        console.print("[red]Error:[/red] Authentication failed")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Decryption failed: {e}")
        sys.exit(1)


@cli.command("encrypt-key")
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--key",
    "-k",
    required=True,
    type=click.Path(exists=True),
    help="Path to the symmetric key file (base64-encoded).",
)
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file path for the encrypted data.",
)
def encrypt_key_cmd(input_file: str, key: str, out: str) -> None:
    """Encrypt a file with a symmetric key file.

    Encrypts INPUT_FILE using AES-256-GCM with the symmetric key
    from the specified key file.

    \b
    Examples:
        shellock encrypt-key config.env --key secret.key --out config.env.enc
    """
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Encrypting with symmetric key...", total=None)
            encrypt_file_key(input_file, out, key)

        console.print(f"[green]✓[/green] Encrypted: {input_file} → {out}")
        sys.exit(0)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except InvalidFileFormatError as e:
        console.print(f"[red]Error:[/red] Invalid key format: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Encryption failed: {e}")
        sys.exit(1)


@cli.command("decrypt-key")
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--key",
    "-k",
    required=True,
    type=click.Path(exists=True),
    help="Path to the symmetric key file (base64-encoded).",
)
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(),
    help="Output file path for the decrypted data.",
)
def decrypt_key_cmd(input_file: str, key: str, out: str) -> None:
    """Decrypt a file with a symmetric key file.

    Decrypts INPUT_FILE using AES-256-GCM with the symmetric key
    from the specified key file.

    \b
    Examples:
        shellock decrypt-key config.env.enc --key secret.key --out config.env
    """
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Decrypting with symmetric key...", total=None)
            decrypt_file_key(input_file, out, key)

        console.print(f"[green]✓[/green] Decrypted: {input_file} → {out}")
        sys.exit(0)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except InvalidFileFormatError:
        console.print("[red]Error:[/red] Invalid file format")
        sys.exit(1)
    except AuthenticationError:
        console.print("[red]Error:[/red] Authentication failed")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Decryption failed: {e}")
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()

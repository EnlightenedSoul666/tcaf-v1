import typer
from config.settings import initialize_directories
from utils.logger import logger
from core.engine import Engine
from clauses.registry import CLAUSE_REGISTRY


app = typer.Typer(
    help="TCAF - Telecom Compliance Automation Framework"
)

@app.command()
def run(
    clause: str = typer.Option(None, "--clause", help="Run a specific clause"),
    section: str = typer.Option(None, "--section", help="Run a section of clauses"),
):
    initialize_directories()

    logger.info("TCAF CLI started")

    # Always ask for DuT IP (needed by all clauses)
    dut_ip = input("Enter DuT IP address: ")

    # Look up what this clause needs from its class declaration
    clause_class = CLAUSE_REGISTRY.get(clause)

    dut_ipv6 = None
    if clause_class and clause_class.REQUIRES_IPV6:
        dut_ipv6 = input("Enter DuT IPv6 address: ")

    ssh_user = None
    ssh_password = None
    if clause_class and clause_class.REQUIRES_SSH:
        ssh_user = input("Enter SSH username: ")
        ssh_password = input("Enter SSH password: ")

    engine = Engine(
        clause=clause,
        section=section,
        ssh_user=ssh_user,
        dut_ip=dut_ip,
        ssh_password=ssh_password,
        dut_ipv6=dut_ipv6
    )

    engine.start()

def main():
    app()


if __name__ == "__main__":
    main()
"""The profile page (read-only)."""

import reflex as rx
from backend.oauth import AuthState
from components.navbar import navbar
from components.footer import footer


def show_as(as_info: list):
    """Show a person in a table row."""
    return rx.table.row(
        rx.table.cell(as_info[1]),  # Name
        rx.table.cell(as_info[0]),  # ASN
    )


@rx.page(route="/profile", on_load=AuthState.obtain_cookie)
def profile() -> rx.Component:
    """The profile page (read-only)."""
    return rx.fragment(
        navbar(),
        rx.center(
            rx.vstack(
                # --- Account header ---
                rx.flex(
                    rx.vstack(
                        rx.heading(f"Account for {AuthState.user.email}", size="5"),
                        align="center",
                    ),
                    width="100%",
                    spacing="4",
                    flex_direction=["column", "column", "row"],
                ),

                rx.divider(),

                # --- Personal information ---
                rx.flex(
                    rx.vstack(
                        rx.hstack(
                            rx.icon("square-user-round"),
                            rx.heading("Personal information", size="5"),
                            align="center",
                            spacing="2",
                        ),
                        rx.text("Your personal information as registered in the system.", size="3"),
                        rx.box(
                            rx.text(f"First name: {AuthState.user.first_name}", size="3"),
                            rx.text(f"Last name: {AuthState.user.last_name}", size="3"),
                            rx.text(f"Country: {AuthState.user.country}", size="3"),
                            spacing="2",
                            display="flex",
                            flex_direction="column",
                            width="100%",
                        ),
                        width="100%",
                        spacing="3",
                    ),
                    width="100%",
                    spacing="4",
                    flex_direction=["column", "column", "row"],
                ),

                rx.divider(),

                # --- Network information ---
                rx.flex(
                    rx.vstack(
                        rx.hstack(
                            rx.icon("bell"),
                            rx.heading("Network information", size="5"),
                            align="center",
                            spacing="2",
                        ),
                        rx.text("ASes associated with your email.", size="3"),
                    ),
                    rx.spacer(),
                    rx.table.root(
                        rx.table.header(
                            rx.table.row(
                                rx.table.column_header_cell("Name"),
                                rx.table.column_header_cell("ASN"),
                            ),
                        ),
                        rx.table.body(
                            rx.foreach(AuthState.asns_info, show_as)
                        ),
                        width="100%",
                        size="3",
                        max_width="325px",
                    ),
                    width="100%",
                    spacing="5",
                    flex_direction=["column", "column", "row"],
                ),

                spacing="6",
                width="100%",
                max_width="800px",
            ),
            width="100%",
            margin_top="5rem",   # 👈 push content below fixed navbar
        ),
        footer()
    )
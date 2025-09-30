import reflex as rx
from backend.oauth import AuthState  # ✅ import your AuthState

max_width = "1800px"  # same value as your table/content

def navbar() -> rx.Component:
    return rx.box(
        rx.flex(
            # --- Left side: brand + main nav ---
            rx.hstack(
                # Brand (flush left)
                rx.link(
                    rx.text(
                        "DFOH",
                        size="6",
                        weight="bold",
                        color=rx.color_mode_cond(
                            light="black",
                            dark="white",
                        ),
                        style={
                            "letterSpacing": "0.05em",
                            "fontFamily": "sans-serif",
                        },
                    ),
                    href="/",
                ),
                # Main nav links
                rx.link(rx.text("New Links", size="4", weight="medium"), href="/"),
                rx.link(rx.text("Your Cases", size="4", weight="medium"), href="/your_cases"),
                rx.link(rx.text("Documentation", size="4", weight="medium"), href="/documentation"),
                spacing="6",
                align="center",
            ),
            rx.spacer(),
            # --- Right side: login / profile ---
            rx.cond(
                AuthState.is_authenticated,
                rx.hstack(
                    rx.link(
                        rx.text("Profile", size="4", weight="medium"),
                        href="/profile",
                    ),
                    rx.link(
                        rx.text("Logout", size="4", weight="medium"),
                        on_click=AuthState.logout,
                        style={"cursor": "pointer"},
                    ),
                    spacing="4",
                ),
                rx.link(
                    rx.text("Login", size="4", weight="medium"),
                    href="/login",
                ),
            ),
            align="center",
            justify="between",
            width="100%",
            max_width=max_width,     # ✅ constrain elements
            margin="0 auto",         # ✅ center content inside full-width bar
            padding_x="2em",
            padding_y="1em",
        ),
        width="100%",                # ✅ full screen background
        bg=rx.color_mode_cond(
            light="#DDDDDD",
            dark="#222222",
        ),
        position="fixed",            # ✅ sticks to top
        top="0",
        z_index="100",
        box_shadow="sm",
    )
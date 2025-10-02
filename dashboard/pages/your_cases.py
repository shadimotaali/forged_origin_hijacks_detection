import reflex as rx
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Optional

from components.navbar import navbar
from components.footer import footer
from backend.oauth import AuthState
import os


CARD_RADIUS = "12px"


# -----------------------------
# Helpers
# -----------------------------
def is_not_connected() -> rx.Component:
    """Shown when the user is not authenticated."""
    return rx.center(
        rx.box(
            rx.vstack(
                rx.text(
                    "You must be logged in to view this page.",
                    size="5",
                    weight="bold",
                    color_scheme="red",
                    text_align="center",
                ),
                rx.text(
                    "Please sign in with your PeeringDB account to continue.",
                    size="4",
                    color_scheme="red",
                    text_align="center",
                ),
                spacing="3",
                align="center",
                width="100%",
            ),
            border="2px solid #e53e3e",
            background="rgba(255, 0, 0, 0.05)",
            border_radius=CARD_RADIUS,
            padding="1.5em",
            width="100%",
            box_shadow="0 2px 8px rgba(229, 62, 62, 0.1)",
        )
    )


def case_is_correct(case_: dict[str, str | int | list[str]]):
    """Validate and normalize a case object."""
    required = [
        "date", "as1", "as2", "presumed_attacker", "presumed_victims",
        "inference_result", "confidence_level", "nb_aspaths_observed",
        "is_reccurent", "id"
    ]
    for k in required:
        if k not in case_:
            return False, None

    return True, (
        case_["date"].replace("T", " "),
        str(case_["as1"]),
        str(case_["as2"]),
        [str(x) for x in case_["presumed_attacker"]],
        [str(x) for x in case_["presumed_victims"]],
        str(case_["inference_result"]),
        int(case_["confidence_level"]),
        int(case_["nb_aspaths_observed"]),
        bool(case_["is_reccurent"]),
        int(case_["id"]),
    )


# -----------------------------
# State: Your Cases
# -----------------------------
class YourCasesState(rx.State):
    """Holds the state for the 'Your Cases' page."""

    links: List[Tuple[str, str, str, List[str], List[str], str, int, int, bool, int]] = []
    loading: bool = False
    error: Optional[str] = None

    # filters
    start_dt_local: str = ""
    end_dt_local: str = ""
    inference_filter: str = "Any"

    # pagination
    page_number: int = 1
    rows_per_page: int = 50
    asns: list[str] = list()

    # ---- API call ----
    @rx.event(background=True)
    async def load_links(self):
        try:
            now = datetime.now(timezone.utc)
            start_time = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M")
            end_time = now.strftime("%Y-%m-%dT%H:%M")

            async with self:
                self.loading = True
                self.error = None

                if self.start_dt_local:
                    start_time = self.start_dt_local
                if self.end_dt_local:
                    end_time = self.end_dt_local

                # user ASNs from AuthState
                self.asns = await self.get_var_value(AuthState.asns)

            params = {
                "asn": ",".join(self.asns),
                "start_time": start_time,
                "end_time": end_time,
                "show_private_asn": True,
            }
            resp = requests.get(
                "https://dfoh-api.bgproutes.io/new_links",
                params=params,
                timeout=10,
            )
            data = resp.json().get("results", []) if resp.status_code == 200 else []

        except Exception as e:
            print(f"Error fetching data: {e}")
            data = []

        parsed = [val for case_ in data if (ok := case_is_correct(case_))[0] for val in [ok[1]] if val]

        async with self:
            self.links = sorted(parsed, key=lambda x: x[0], reverse=True)
            self.loading = False
            self.page_number = 1

    # --- setters ---
    @rx.event
    def set_start(self, v: str): self.start_dt_local = v

    @rx.event
    def set_end(self, v: str): self.end_dt_local = v

    @rx.event
    def set_inference(self, v: str): self.inference_filter = v

    # --- pagination ---
    @rx.var
    def total_pages(self) -> int:
        return (len(self.links) + self.rows_per_page - 1) // self.rows_per_page or 1

    @rx.var
    def get_current_page(self) -> List[Tuple[str, str, str, List[str], List[str], str, int, int, bool, int]]:
        start = (self.page_number - 1) * self.rows_per_page
        end = start + self.rows_per_page
        return self.links[start:end]

    @rx.event
    def first_page(self): self.page_number = 1

    @rx.event
    def last_page(self): self.page_number = self.total_pages

    @rx.event
    def next_page(self):
        if self.page_number < self.total_pages:
            self.page_number += 1

    @rx.event
    def prev_page(self):
        if self.page_number > 1:
            self.page_number -= 1

    @rx.event
    def set_page(self, n: int):
        if 1 <= n <= self.total_pages:
            self.page_number = n


# -----------------------------
# State: Operator Feedback
# -----------------------------
class OperatorFeedbackState(rx.State):
    """Handle operator feedback modal + submission."""

    show_modal: bool = False
    current_case_id: Optional[int] = None
    decision: Optional[str] = None   # "legitimate", "suspicious", or "unknown"
    feedback_text: str = ""
    authorize_others: bool = True     # ✅ default checked
    grant_feedback_use: bool = False  # ✅ default unchecked

    # -----------------------------
    # Modal helpers
    # -----------------------------
    @rx.event
    def open_modal(self, case_id: int):
        self.show_modal = True
        self.current_case_id = case_id
        self.decision = None
        self.feedback_text = ""
        self.authorize_others = True
        self.grant_feedback_use = False   # reset to default

    @rx.event
    def close_modal(self):
        self.show_modal = False
        self.current_case_id = None
        self.decision = None
        self.feedback_text = ""
        self.authorize_others = True
        self.grant_feedback_use = False

    # -----------------------------
    # Field setters
    # -----------------------------
    @rx.event
    def set_feedback(self, text: str):
        self.feedback_text = text

    @rx.event
    def set_decision(self, decision: str):
        self.decision = decision

    @rx.event
    def toggle_authorize(self, value: bool):
        self.authorize_others = value

    @rx.event
    def toggle_feedback_use(self, value: bool):
        self.grant_feedback_use = value

    # -----------------------------
    # API submission
    # -----------------------------
    @rx.event(background=True)
    async def submit_feedback(self):
        """Send operator feedback to the API."""
        if not self.current_case_id or not self.decision:
            return rx.toast.error("Please choose validate/contest first")

        try:
            resp = requests.get(
                "https://dfoh-api.bgproutes.io/operator_feedback",
                params={
                    "new_link_id": self.current_case_id,
                    "decision": self.decision,
                    "feedback": self.feedback_text,
                    "authorize_others": "true" if self.authorize_others else "false",
                    "grant_feedback_use": "true" if self.grant_feedback_use else "false",
                    "api_key": os.environ.get("SECURED_WRITE_API_KEY"),
                },
                timeout=10,
            )
            if resp.status_code == 200:
                rx.toast.success("Feedback submitted, thank you!")
            else:
                rx.toast.error(f"Error {resp.status_code}: {resp.text}")

        except Exception as e:
            print(f"Error submitting feedback: {e}")
            rx.toast.error("Could not reach feedback API.")

        # ✅ safely reset state inside background context
        async with self:
            self.show_modal = False
            self.current_case_id = None
            self.decision = None
            self.feedback_text = ""


# -----------------------------
# UI helpers
# -----------------------------
def _badge_link(asn: str) -> rx.Component:
    return rx.badge(
        rx.link(asn, href="https://bgp.he.net/AS" + asn, target="_blank"),
        style={"verticalAlign": "middle"},
    )


def _attacker_cell(values: List[str]) -> rx.Component:
    return rx.table.cell(
        rx.box(
            rx.foreach(
                values,
                lambda x: rx.badge(rx.link(x, href="https://bgp.he.net/AS" + x, target="_blank")),
            ),
            style={"display": "flex", "flexWrap": "wrap"},
        ),
        style={"verticalAlign": "middle"},
    )


def _victim_cell(values: List[str]) -> rx.Component:
    return rx.table.cell(
        rx.cond(
            values.length() > 6,
            rx.hover_card.root(
                rx.hover_card.trigger(
                    rx.badge(f"{values.length()} victims", variant="surface", style={"cursor": "pointer"})
                ),
                rx.hover_card.content(
                    rx.box(
                        rx.foreach(
                            values,
                            lambda x: rx.badge(rx.link(x, href="https://bgp.he.net/AS" + x, target="_blank")),
                        ),
                        style={"display": "flex", "flexWrap": "wrap", "maxWidth": "360px"},
                    )
                ),
            ),
            rx.box(
                rx.foreach(
                    values,
                    lambda x: rx.badge(rx.link(x, href="https://bgp.he.net/AS" + x, target="_blank")),
                ),
                style={"display": "flex", "flexWrap": "wrap"},
            ),
        ),
        style={"verticalAlign": "middle"},
    )


def yourcases_filters_panel() -> rx.Component:
    return rx.card(
        rx.form.root(
            rx.vstack(
                rx.hstack(
                    rx.box(
                        rx.text("Start (UTC)", size="2", weight="medium"),
                        rx.input(
                            type="datetime-local",
                            value=YourCasesState.start_dt_local,
                            on_change=YourCasesState.set_start,
                        ),
                        width="50%",
                    ),
                    rx.box(
                        rx.text("End (UTC)", size="2", weight="medium"),
                        rx.input(
                            type="datetime-local",
                            value=YourCasesState.end_dt_local,
                            on_change=YourCasesState.set_end,
                        ),
                        width="50%",
                    ),
                    spacing="4",
                    width="100%",
                ),
                rx.box(
                    rx.text("Inference result", size="2", weight="medium"),
                    rx.select(
                        items=["Any", "legitimate", "suspicious"],
                        value=YourCasesState.inference_filter,
                        on_change=YourCasesState.set_inference,
                        width="100%",
                    ),
                ),
                rx.hstack(
                    rx.button("Submit", type="submit", variant="solid", size="2"),
                    spacing="3",
                    mt="3",
                ),
            ),
            on_submit=YourCasesState.load_links,
        ),
        style={"border": "1px solid var(--gray-5)"},
    )


def _pagination_view() -> rx.Component:
    return rx.hstack(
        rx.text(
            "Page ",
            rx.code(YourCasesState.page_number),
            f" of {YourCasesState.total_pages}",
            justify="end",
        ),
        rx.hstack(
            rx.icon_button(
                rx.icon("chevrons-left", size=18),
                on_click=YourCasesState.first_page,
                opacity=rx.cond(YourCasesState.page_number == 1, 0.6, 1),
                color_scheme=rx.cond(YourCasesState.page_number == 1, "gray", "accent"),
                variant="soft",
            ),
            rx.icon_button(
                rx.icon("chevron-left", size=18),
                on_click=YourCasesState.prev_page,
                opacity=rx.cond(YourCasesState.page_number == 1, 0.6, 1),
                color_scheme=rx.cond(YourCasesState.page_number == 1, "gray", "accent"),
                variant="soft",
            ),
            rx.icon_button(
                rx.icon("chevron-right", size=18),
                on_click=YourCasesState.next_page,
                opacity=rx.cond(
                    YourCasesState.page_number == YourCasesState.total_pages, 0.6, 1
                ),
                color_scheme=rx.cond(
                    YourCasesState.page_number == YourCasesState.total_pages,
                    "gray",
                    "accent",
                ),
                variant="soft",
            ),
            rx.icon_button(
                rx.icon("chevrons-right", size=18),
                on_click=YourCasesState.last_page,
                opacity=rx.cond(
                    YourCasesState.page_number == YourCasesState.total_pages, 0.6, 1
                ),
                color_scheme=rx.cond(
                    YourCasesState.page_number == YourCasesState.total_pages,
                    "gray",
                    "accent",
                ),
                variant="soft",
            ),
            align="center",
            spacing="2",
            justify="end",
        ),
        spacing="5",
        margin_top="1em",
        align="center",
        width="100%",
        justify="end",
    )


def operator_feedback_modal() -> rx.Component:
    return rx.dialog.root(
        rx.dialog.content(
            rx.dialog.title("Operator Feedback"),
            rx.dialog.description("Validate or contest the inference, and provide feedback."),
            rx.vstack(
                rx.hstack(
                    rx.button(
                        "Legitimate",
                        color_scheme="green",
                        on_click=lambda: OperatorFeedbackState.set_decision("legitimate"),
                        variant=rx.cond(
                            OperatorFeedbackState.decision == "legitimate", "solid", "soft"
                        ),
                    ),
                    rx.button(
                        "Suspicious",
                        color_scheme="red",
                        on_click=lambda: OperatorFeedbackState.set_decision("suspicious"),
                        variant=rx.cond(
                            OperatorFeedbackState.decision == "suspicious", "solid", "soft"
                        ),
                    ),
                    rx.button(
                        "Unknown",
                        color_scheme="orange",
                        on_click=lambda: OperatorFeedbackState.set_decision("unknown"),
                        variant=rx.cond(
                            OperatorFeedbackState.decision == "unknown", "solid", "soft"
                        ),
                    ),
                    spacing="4",
                ),
                rx.text_area(
                    placeholder="Write your feedback here…",
                    value=OperatorFeedbackState.feedback_text,
                    on_change=OperatorFeedbackState.set_feedback,
                    width="100%",
                ),
                rx.checkbox(
                    "Authorize other operators to see my feedback",
                    checked=OperatorFeedbackState.authorize_others,
                    on_change=OperatorFeedbackState.toggle_authorize,
                ),
                rx.checkbox(
                    "Authorize my feedback to be used anonymously",
                    checked=OperatorFeedbackState.grant_feedback_use,
                    on_change=OperatorFeedbackState.toggle_feedback_use,
                ),
                rx.button(
                    "Submit",
                    on_click=OperatorFeedbackState.submit_feedback,
                    width="100%",
                ),
                spacing="4",
                width="100%",
            ),
            rx.dialog.close(
                rx.button("Cancel", on_click=OperatorFeedbackState.close_modal, variant="soft"),
            ),
            style={"maxWidth": "520px"},
        ),
        open=OperatorFeedbackState.show_modal,
        on_open_change=OperatorFeedbackState.close_modal,
    )


def yourcases_table() -> rx.Component:
    return rx.card(
        _pagination_view(),
        rx.table.root(
            rx.table.header(
                rx.table.row(
                    rx.table.column_header_cell("Date", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("AS1", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("AS2", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("Presumed Attacker", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("Presumed Victims", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("Inference", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("Observed Paths", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("Recurrent", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("Details", style={"verticalAlign": "middle"}),
                    rx.table.column_header_cell("Give feedback", style={"verticalAlign": "middle"}),  # NEW
                ),
                style={
                    "position": "sticky",
                    "top": 0,
                    "zIndex": 1,
                    "backgroundColor": "var(--gray-1)",
                    "backdropFilter": "blur(2px)",
                },
            ),
            rx.table.body(
                rx.cond(
                    YourCasesState.loading,
                    rx.table.row(
                        rx.table.cell(
                            "Loading…",
                            col_span=10,
                            style={"textAlign": "center", "fontStyle": "italic"},
                        )
                    ),
                    rx.cond(
                        YourCasesState.get_current_page.length() == 0,
                        rx.table.row(
                            rx.table.cell(
                                "No data matches your filters.",
                                col_span=10,
                                style={"textAlign": "center", "fontStyle": "italic"},
                            )
                        ),
                        rx.foreach(
                            YourCasesState.get_current_page,
                            lambda row: rx.table.row(
                                rx.table.cell(row[0], style={"verticalAlign": "middle"}),
                                rx.table.cell(_badge_link(row[1]), style={"verticalAlign": "middle"}),
                                rx.table.cell(_badge_link(row[2]), style={"verticalAlign": "middle"}),
                                _attacker_cell(row[3]),
                                _victim_cell(row[4]),
                                rx.table.cell(
                                    row[5],
                                    style=rx.cond(
                                        row[5] == "legitimate",
                                        {"verticalAlign": "middle", "backgroundColor": "var(--green-3)"},
                                        {"verticalAlign": "middle", "backgroundColor": "var(--red-3)"},
                                    ),
                                ),
                                rx.table.cell(row[7], style={"verticalAlign": "middle"}),
                                rx.table.cell(
                                    rx.cond(row[8], rx.text("Yes"), rx.text("No")),
                                    style={"verticalAlign": "middle"},
                                ),
                                rx.table.cell(
                                    rx.link(
                                        rx.button(
                                            "Details",
                                            size="1",
                                            variant="soft",
                                            left_icon="info",
                                        ),
                                        href=f"/detail/{row[9]}",
                                    ),
                                    style={"textAlign": "center", "verticalAlign": "middle"},
                                ),
                                rx.table.cell(
                                    rx.cond(
                                        YourCasesState.asns.contains(row[2]),
                                        rx.button(
                                            "Operator Feedback",
                                            size="1",
                                            variant="outline",
                                            on_click=lambda: OperatorFeedbackState.open_modal(row[9]),
                                        ),
                                        rx.text("-"),
                                    ),
                                    style={"textAlign": "center", "verticalAlign": "middle"},
                                ),
                            ),
                        ),
                    ),
                )
            ),
            size="3",
            variant="surface",
            style={"--table-row-hover-bg": "var(--gray-2)"},
        ),
        _pagination_view(),
        width="100%",
        style={
            "overflowX": "auto",
            "border": "1px solid var(--gray-5)",
            "boxShadow": "0 2px 8px rgba(0,0,0,0.06)",
        },
    )


# -----------------------------
# Page
# -----------------------------
@rx.page(
    route="/your_cases",
    on_load=[
        YourCasesState.load_links,
        AuthState.run_oauth_callback,  # must be an event
    ],
)
def your_cases() -> rx.Component:
    return rx.fragment(
        navbar(),
        rx.box(
            rx.cond(
                AuthState.is_authenticated,
                rx.vstack(
                    rx.heading("Your Cases", size="7", mb="4"),
                    yourcases_filters_panel(),
                    yourcases_table(),
                    spacing="6",
                    width="100%",
                    style={"maxWidth": "1600px", "margin": "0 auto"},
                ),
                is_not_connected(),
            ),
            margin_top="5rem",   # push below fixed navbar
        ),
        operator_feedback_modal(),   # modal lives at page level
        footer(),
    )


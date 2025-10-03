import reflex as rx
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Optional

from components.navbar import navbar
from components.footer import footer
from backend.oauth import AuthState
import os


CARD_RADIUS = "12px"


api_base_url = os.environ.get("API_URL", "https://dfoh-api.bgproutes.io")

DECISION_LEGITIMATE = 1
DECISION_MALICIOUS = 2
DECISION_UNKNOWN = 3


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


def parse_decision(decision: int):
    if decision == DECISION_LEGITIMATE:
        return "Legitimate"
    elif decision == DECISION_MALICIOUS:
        return "Malicious"
    elif decision == DECISION_UNKNOWN:
        return "Interesting"
    return ""


def case_is_correct(case_: dict[str, str | int | list[str]]):
    required = [
        "date",
        "as1",
        "as2",
        "presumed_attacker",
        "presumed_victims",
        "inference_result",
        "confidence_level",
        "nb_aspaths_observed",
        "is_reccurent",
        "id",
    ]

    for k in required:
        if k not in case_:
            return False, None

    feedback = ""
    comment = ""

    if "operator_feedback" in case_ and "operator_comment" in case_:
        feedback = parse_decision(int(case_["operator_feedback"]))
        comment = str(case_["operator_comment"])

    return True, (
        case_["date"].replace("T", " "),  # 0 date
        str(case_["as1"]),  # 1 as1
        str(case_["as2"]),  # 2 as2
        [str(x) for x in case_["presumed_attacker"]],  # 3 attackers
        [str(x) for x in case_["presumed_victims"]],  # 4 victims
        str(case_["inference_result"]),  # 5 inference_result
        int(case_["confidence_level"]),  # 6 confidence
        int(case_["nb_aspaths_observed"]),  # 7 nb paths
        bool(case_["is_reccurent"]),  # 8 recurrent
        int(case_["id"]),  # 9 id
        str(feedback),  # 10 feedback
        str(comment),  # 11 comment
    )


# -----------------------------
# State: Your Cases
# -----------------------------
class YourCasesState(rx.State):
    """Holds the state for the 'Your Cases' page."""

    links: List[
        Tuple[str, str, str, List[str], List[str], str, int, int, bool, int, str, str]
    ] = []
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

    # --------------------
    # Init time window
    # --------------------
    @rx.event
    def init_time_window(self):
        now_utc = datetime.now(timezone.utc)
        self.end_dt_local = now_utc.strftime("%Y-%m-%dT%H:%M")
        self.start_dt_local = (now_utc - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M")

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
                f"{api_base_url}/new_links",
                params=params,
                timeout=10,
            )
            data = resp.json().get("results", []) if resp.status_code == 200 else []

        except Exception as e:
            print(f"Error fetching data: {e}")
            data = []

        parsed = [
            val
            for case_ in data
            if (ok := case_is_correct(case_))[0]
            for val in [ok[1]]
            if val
        ]

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
    def get_current_page(
        self,
    ) -> List[Tuple[str, str, str, List[str], List[str], str, int, int, bool, int, str, str]]:
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
    decision: Optional[str] = None
    feedback_text: str = ""
    authorize_others: bool = True
    grant_feedback_use: bool = True

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
        self.grant_feedback_use = True

    @rx.event
    def close_modal(self):
        self.show_modal = False
        self.current_case_id = None
        self.decision = None
        self.feedback_text = ""
        self.authorize_others = True
        self.grant_feedback_use = True

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
            return rx.toast.error("You need to select a decision")   # ✅ clearer message

        try:
            resp = requests.get(
                f"{api_base_url}/operator_feedback",
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




def _your_feedback_cell(feedback: rx.Var[str], comment: rx.Var[str]) -> rx.Component:
    """Show colored rectangle with decision text and click-to-open comment box."""
    return rx.table.cell(
        rx.cond(
            feedback,
            rx.hover_card.root(
                # --- clickable trigger ---
                rx.hover_card.trigger(
                    rx.box(
                        rx.text(
                            feedback,
                            size="2",
                            weight="bold",
                            color=rx.cond(
                                feedback == "Legitimate",
                                "var(--green-11)",
                                rx.cond(
                                    feedback == "Malicious",
                                    "var(--red-11)",
                                    rx.cond(feedback == "Interesting", "var(--orange-11)", "var(--gray-4)"),
                                )
                            )
                        ),
                        style={
                            "padding": "0.3rem 0.7rem",
                            "borderRadius": "6px",
                            "cursor": "pointer",
                            "display": "inline-block",
                            "textAlign": "center",
                            "backgroundColor": rx.cond(
                                feedback == "Legitimate",
                                "var(--green-3)",
                                rx.cond(
                                    feedback == "Malicious",
                                    "var(--red-3)",
                                    rx.cond(feedback == "Interesting", "var(--orange-3)", "var(--gray-4)"),
                                ),
                            ),
                        },
                    )
                ),
                # --- popup content ---
                rx.hover_card.content(
                    rx.vstack(
                        rx.text("Decision: " + feedback, weight="medium"),
                        rx.cond(comment, rx.text("Comment: " + comment), rx.text("No comment")),
                        spacing="2",
                        align="start",
                    ),
                    style={
                        "padding": "0.75rem",
                        "maxWidth": "320px",
                        "whiteSpace": "normal",
                        "backgroundColor": "white",
                        "border": "1px solid var(--gray-6)",
                        "borderRadius": "6px",
                        "boxShadow": "0 6px 16px rgba(0,0,0,0.15)",
                    },
                ),
            ),
            rx.text("-", style={"color": "var(--gray-8)"})
        ),
        style={"verticalAlign": "middle", "textAlign": "center"},
    )




# -----------------------------
# Filters
# -----------------------------
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


# -----------------------------
# Pagination
# -----------------------------
def _pagination_view() -> rx.Component:
    return rx.hstack(
        rx.text("Page ", rx.code(YourCasesState.page_number), f" of {YourCasesState.total_pages}", justify="end"),
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
                opacity=rx.cond(YourCasesState.page_number == YourCasesState.total_pages, 0.6, 1),
                color_scheme=rx.cond(YourCasesState.page_number == YourCasesState.total_pages, "gray", "accent"),
                variant="soft",
            ),
            rx.icon_button(
                rx.icon("chevrons-right", size=18),
                on_click=YourCasesState.last_page,
                opacity=rx.cond(YourCasesState.page_number == YourCasesState.total_pages, 0.6, 1),
                color_scheme=rx.cond(YourCasesState.page_number == YourCasesState.total_pages, "gray", "accent"),
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


# -----------------------------
# Feedback Modal
# -----------------------------
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
                        variant=rx.cond(OperatorFeedbackState.decision == "legitimate", "solid", "soft"),
                    ),
                    rx.button(
                        "Suspicious",
                        color_scheme="red",
                        on_click=lambda: OperatorFeedbackState.set_decision("suspicious"),
                        variant=rx.cond(OperatorFeedbackState.decision == "suspicious", "solid", "soft"),
                    ),
                    rx.button(
                        "Interesting",
                        color_scheme="orange",
                        on_click=lambda: OperatorFeedbackState.set_decision("unknown"),
                        variant=rx.cond(OperatorFeedbackState.decision == "unknown", "solid", "soft"),
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
                rx.button("Submit", on_click=OperatorFeedbackState.submit_feedback, width="100%"),
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


# -----------------------------
# Table
# -----------------------------
def yourcases_table() -> rx.Component:
    return rx.card(
        _pagination_view(),
        rx.table.root(
            rx.table.header(
                rx.table.row(
                    rx.table.column_header_cell("Date"),
                    rx.table.column_header_cell("AS1"),
                    rx.table.column_header_cell("AS2"),
                    rx.table.column_header_cell("Attacker(s)"),
                    rx.table.column_header_cell("Victim(s)"),
                    rx.table.column_header_cell("Inference"),
                    rx.table.column_header_cell("# Paths"),
                    rx.table.column_header_cell("Recurrent"),
                    rx.table.column_header_cell("Details"),
                    rx.table.column_header_cell("Your Feedback"),
                    rx.table.column_header_cell("Give Feedback"),
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
                            "Loading…", col_span=11, style={"textAlign": "center", "fontStyle": "italic"}
                        )
                    ),
                    rx.cond(
                        YourCasesState.get_current_page.length() == 0,
                        rx.table.row(
                            rx.table.cell(
                                "No data matches your filters.",
                                col_span=11,
                                style={"textAlign": "center", "fontStyle": "italic"},
                            )
                        ),
                        rx.foreach(
                            YourCasesState.get_current_page,
                            lambda row: rx.table.row(
                                rx.table.cell(row[0], style={"verticalAlign": "middle"},),
                                rx.table.cell(_badge_link(row[1]), style={"verticalAlign": "middle"},),
                                rx.table.cell(_badge_link(row[2]), style={"verticalAlign": "middle"},),
                                _attacker_cell(row[3]),
                                _victim_cell(row[4]),
                                rx.table.cell(
                                    row[5],
                                    style=rx.cond(
                                        row[5] == "legitimate",
                                        {"backgroundColor": "var(--green-3)", "verticalAlign": "middle"},
                                        {"backgroundColor": "var(--red-3)", "verticalAlign": "middle"},
                                    )
                                ),
                                rx.table.cell(row[7], style={"verticalAlign": "middle"}),
                                rx.table.cell(rx.cond(row[8], rx.text("Yes"), rx.text("No")), style={"verticalAlign": "middle"}),
                                rx.table.cell(
                                    rx.link(
                                        rx.button("Details", size="1", variant="soft", left_icon="info"),
                                        href=f"/detail/{row[9]}",
                                    ),
                                    style={"verticalAlign": "middle"},
                                ),
                                _your_feedback_cell(row[10], row[11]),
                                rx.table.cell(
                                    rx.cond(
                                        YourCasesState.asns.contains(row[2]),
                                        rx.button(
                                            "Give us Feedback!",
                                            size="2",
                                            color_scheme="blue",   # not critical; styles below dominate
                                            variant="solid",
                                            left_icon="edit-3",
                                            on_click=lambda: OperatorFeedbackState.open_modal(row[9]),
                                            style={
                                                # shape & spacing
                                                "display": "inline-flex",
                                                "alignItems": "center",
                                                "gap": "0.3rem",
                                                "borderRadius": "9999px",      # pill
                                                "padding": "0.25rem 0.6rem",
                                                "fontWeight": "800",
                                                "letterSpacing": "0.01em",

                                                # solid, high-contrast look (no gradient)
                                                "backgroundColor": "var(--blue-9)",
                                                "border": "3px solid var(--blue-12)",
                                                "color": "white",

                                                # subtle depth + snappy interactions
                                                "boxShadow": "0 6px 16px rgba(0,0,0,0.18)",
                                                "transition": "transform 0.15s ease, box-shadow 0.15s ease, background-color 0.15s ease, border-color 0.15s ease",
                                                "cursor": "pointer",
                                            },
                                            _hover={
                                                "transform": "translateY(-1px)",
                                                "backgroundColor": "var(--blue-10)",
                                                "borderColor": "var(--blue-12)",
                                                "boxShadow": "0 10px 22px rgba(0,0,0,0.22)",
                                            },
                                            _active={
                                                "transform": "translateY(0)",
                                                "backgroundColor": "var(--blue-9)",
                                                "boxShadow": "0 5px 14px rgba(0,0,0,0.18)",
                                            },
                                            _focus={
                                                "outline": "none",
                                                "boxShadow": "0 0 0 4px rgba(30, 64, 175, 0.35)",  # blue focus ring
                                            },
                                        ),
                                        rx.text("-"),
                                    ),
                                    style={"verticalAlign": "middle"},  # no background behind the button
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
    on_load=[YourCasesState.init_time_window, YourCasesState.load_links, AuthState.run_oauth_callback],
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
            margin_top="5rem",
        ),
        operator_feedback_modal(),
        footer(),
    )


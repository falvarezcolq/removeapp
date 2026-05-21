from __future__ import annotations

import subprocess
import traceback
from typing import Dict, List

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QMenu,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStyle,
    QStatusBar,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .models import CandidatePath, DeepScanItem, OrphanPath, RiskLevel
from .scanner import deep_scan_app, is_system_protected_app, list_installed_apps, list_orphan_leftovers
from .uninstaller import refresh_launch_services, uninstall_paths

_RISK_LABELS = {
    RiskLevel.LOW: "Bajo",
    RiskLevel.MEDIUM: "Medio",
    RiskLevel.HIGH: "Alto",
    RiskLevel.CRITICAL: "Critico",
}

_RISK_ORDER = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
}

_RISK_BG = {
    RiskLevel.LOW: QColor("#0f3f52"),
    RiskLevel.MEDIUM: QColor("#5a4d1d"),
    RiskLevel.HIGH: QColor("#5c2d2d"),
    RiskLevel.CRITICAL: QColor("#4b2757"),
}

_BUCKET_ORDER = [
    "Newest Items",
    "From 10 MB to 100 MB",
    "From 100 MB to 1 GB",
    "From 1 GB+",
]


def _style_dialog(dlg: QDialog) -> None:
    dlg.setStyleSheet(
        """
        QDialog { background: #0a2f4b; color: #e8f4ff; }
        QLabel#dialogTitle { font-size: 20px; font-weight: 700; color: #f4fbff; }
        QLabel#dialogHint { color: #9cc4e2; font-size: 12px; }
        QTextEdit {
            background: #07263d;
            color: #dcefff;
            border: 1px solid #1f648f;
            border-radius: 8px;
            padding: 8px;
            font-family: Menlo, monospace;
            font-size: 11px;
        }
        QPushButton {
            background: #145c89;
            color: #f0f8ff;
            border: 1px solid #2f84bc;
            border-radius: 9px;
            padding: 7px 12px;
            min-width: 92px;
        }
        QPushButton:hover { background: #1c6ea2; }
        QPushButton#dangerAction {
            background: #8a2a3d;
            border-color: #bb4a60;
        }
        """
    )


def _show_result_dialog(parent: QWidget, title: str, message: str, detail_text: str = "") -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(760, 340)
    _style_dialog(dlg)

    layout = QVBoxLayout(dlg)
    title_label = QLabel(title)
    title_label.setObjectName("dialogTitle")
    layout.addWidget(title_label)

    info = QLabel("Puedes copiar el contenido para auditoria o soporte.")
    info.setObjectName("dialogHint")
    layout.addWidget(info)

    text_area = QTextEdit()
    text_area.setReadOnly(True)
    text_area.setPlainText(message)
    layout.addWidget(text_area)

    if detail_text:
        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setPlainText(detail_text)
        detail.setMaximumHeight(120)
        layout.addWidget(detail)

    actions = QHBoxLayout()
    actions.addStretch(1)
    btn_copy = QPushButton("Copiar")
    btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(message + ("\n\n" + detail_text if detail_text else "")))
    btn_ok = QPushButton("Aceptar")
    btn_ok.clicked.connect(dlg.accept)
    actions.addWidget(btn_copy)
    actions.addWidget(btn_ok)
    layout.addLayout(actions)
    dlg.exec_()


def _ask_confirm_dialog(parent: QWidget, title: str, question: str) -> bool:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(560, 220)
    _style_dialog(dlg)

    layout = QVBoxLayout(dlg)
    title_label = QLabel(title)
    title_label.setObjectName("dialogTitle")
    layout.addWidget(title_label)

    msg = QLabel(question)
    msg.setWordWrap(True)
    layout.addWidget(msg)

    hint = QLabel("Esta accion puede eliminar archivos permanentemente segun tu seleccion.")
    hint.setObjectName("dialogHint")
    layout.addWidget(hint)

    actions = QHBoxLayout()
    actions.addStretch(1)
    btn_cancel = QPushButton("Cancelar")
    btn_cancel.clicked.connect(dlg.reject)
    btn_confirm = QPushButton("Continuar")
    btn_confirm.setObjectName("dangerAction")
    btn_confirm.clicked.connect(dlg.accept)
    actions.addWidget(btn_cancel)
    actions.addWidget(btn_confirm)
    layout.addLayout(actions)

    return dlg.exec_() == QDialog.Accepted


def _show_error_dialog(parent: QWidget, title: str, error_text: str) -> None:
    _show_result_dialog(
        parent,
        title,
        "Se produjo un error. Revisa y copia el detalle tecnico:",
        error_text,
    )


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return "{} B".format(size_bytes)
    if size_bytes < 1024 ** 2:
        return "{:.1f} KB".format(size_bytes / 1024)
    if size_bytes < 1024 ** 3:
        return "{:.1f} MB".format(size_bytes / 1024 ** 2)
    return "{:.2f} GB".format(size_bytes / 1024 ** 3)


def _size_bucket(size_bytes: int) -> str:
    if size_bytes >= 1024 ** 3:
        return "From 1 GB+"
    if size_bytes >= 100 * 1024 ** 2:
        return "From 100 MB to 1 GB"
    if size_bytes >= 10 * 1024 ** 2:
        return "From 10 MB to 100 MB"
    return "Newest Items"


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("RemoveApp - App Cleaner & Uninstaller")
        self.resize(1320, 780)

        self.current_deep_items: List[DeepScanItem] = []
        self.current_orphans: List[OrphanPath] = []
        self.category_items: Dict[str, List[DeepScanItem]] = {}
        self.category_totals: Dict[str, int] = {}
        self.checked_paths: Dict[str, bool] = {}
        self.checked_orphans: Dict[str, bool] = {}
        self.active_category = ""

        root = QWidget()
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        sidebar = self._build_sidebar()
        content = self._build_content()
        shell.addWidget(sidebar)
        shell.addWidget(content, 1)

        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self._apply_styles()
        self.load_installed_apps()

    def _build_sidebar(self) -> QWidget:
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(210)
        layout = QVBoxLayout(side)
        layout.setContentsMargins(16, 20, 16, 20)
        layout.setSpacing(10)

        title = QLabel("RemoveApp")
        title.setObjectName("sidebarTitle")
        layout.addWidget(title)

        nav_items = [
            ("Applications", QStyle.SP_DirIcon),
            ("Startup Programs", QStyle.SP_ComputerIcon),
            ("Extensions", QStyle.SP_DriveHDIcon),
            ("Remaining Files", QStyle.SP_FileIcon),
            ("Updates", QStyle.SP_BrowserReload),
        ]
        for name, icon_id in nav_items:
            btn = QPushButton(name)
            btn.setObjectName("sideNav")
            btn.setIcon(self.style().standardIcon(icon_id))
            btn.setIconSize(QSize(16, 16))
            btn.setCheckable(True)
            btn.setChecked(name == "Applications")
            btn.setEnabled(False)
            layout.addWidget(btn)

        layout.addStretch(1)
        footer = QLabel("Local Cleaner")
        footer.setObjectName("sidebarFooter")
        layout.addWidget(footer)
        return side

    def _build_content(self) -> QWidget:
        wrapper = QWidget()
        body = QVBoxLayout(wrapper)
        body.setContentsMargins(22, 18, 22, 18)
        body.setSpacing(12)

        head = QHBoxLayout()
        labels_col = QVBoxLayout()
        title = QLabel("App Cleaner & Uninstaller")
        title.setObjectName("mainTitle")
        subtitle = QLabel("Detecta aplicaciones, restos y extensiones con riesgo clasificado")
        subtitle.setObjectName("mainSubtitle")
        labels_col.addWidget(title)
        labels_col.addWidget(subtitle)
        self.btn_reset = QPushButton("Limpiar todo")
        self.btn_reset.setObjectName("dangerBtn")
        self.btn_reset.clicked.connect(self.handle_reset)
        head.addLayout(labels_col)
        head.addStretch(1)
        head.addWidget(self.btn_reset)

        search = QHBoxLayout()
        self.input_name = QComboBox()
        self.input_name.setEditable(True)
        self.input_name.setInsertPolicy(QComboBox.NoInsert)
        self.input_name.lineEdit().setPlaceholderText("Selecciona o escribe una app...")
        self.btn_refresh_apps = QPushButton("Refrescar")
        self.btn_refresh_apps.clicked.connect(self.load_installed_apps)
        self.btn_scan = QPushButton("Escanear")
        self.btn_scan.clicked.connect(self.handle_scan)
        self.btn_fix_ls = QPushButton("Reparar App Switcher")
        self.btn_fix_ls.clicked.connect(self.handle_fix_launch_services)
        search.addWidget(QLabel("Search"))
        search.addWidget(self.input_name, 1)
        search.addWidget(self.btn_refresh_apps)
        search.addWidget(self.btn_scan)
        search.addWidget(self.btn_fix_ls)

        self.widget_installed_apps = QListWidget()
        self.widget_installed_apps.itemClicked.connect(self.handle_app_selected)

        self.tree_categories = QTreeWidget()
        self.tree_categories.setHeaderHidden(True)
        self.tree_categories.itemClicked.connect(self.handle_category_tree_clicked)

        self.lbl_bundle_id = QLabel("Bundle ID: -")
        self.lbl_bundle_id.setObjectName("bundleInfo")

        self.tree_results = QTreeWidget()
        self.tree_results.setColumnCount(5)
        self.tree_results.setHeaderLabels(["", "Archivo", "Tamano", "Riesgo", "Detalle"])
        self.tree_results.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree_results.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tree_results.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tree_results.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tree_results.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tree_results.itemClicked.connect(self.handle_tree_item_clicked)
        self.tree_results.itemChanged.connect(self.handle_tree_item_changed)

        center = QHBoxLayout()
        center.setSpacing(10)

        left_panel = QFrame()
        left_panel.setObjectName("card")
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("Aplicaciones instaladas"))
        left_layout.addWidget(self.widget_installed_apps, 1)

        middle_panel = QFrame()
        middle_panel.setObjectName("card")
        middle_layout = QVBoxLayout(middle_panel)
        middle_layout.addWidget(QLabel("Categorias detectadas"))
        middle_layout.addWidget(self.tree_categories, 1)

        right_panel = QFrame()
        right_panel.setObjectName("card")
        right_layout = QVBoxLayout(right_panel)
        right_layout.addWidget(self.lbl_bundle_id)
        right_layout.addWidget(self.tree_results, 1)

        center.addWidget(left_panel, 24)
        center.addWidget(middle_panel, 24)
        center.addWidget(right_panel, 52)

        action = QHBoxLayout()
        self.btn_select_all = QPushButton("Seleccionar visibles")
        self.btn_select_all.clicked.connect(self.select_all)
        self.btn_high_risk_only = QPushButton("Solo Alto/Critico")
        self.btn_high_risk_only.clicked.connect(self.select_high_risk_only)
        self.chk_permanent = QCheckBox("Eliminar permanente")
        self.btn_uninstall = QPushButton("Remove")
        self.btn_uninstall.setObjectName("primaryBtn")
        self.btn_uninstall.clicked.connect(self.handle_uninstall)
        self.lbl_selection_badge = QLabel("0")
        self.lbl_selection_badge.setObjectName("selectionBadge")
        self.lbl_selection_badge.setVisible(False)
        action.addWidget(self.btn_select_all)
        action.addWidget(self.btn_high_risk_only)
        action.addStretch(1)
        action.addWidget(self.chk_permanent)
        action.addWidget(self.btn_uninstall)
        action.addWidget(self.lbl_selection_badge)

        orphan_card = QFrame()
        orphan_card.setObjectName("card")
        orphan_layout = QVBoxLayout(orphan_card)
        orphan_head = QHBoxLayout()
        orphan_head.addWidget(QLabel("Restos huerfanos"))
        self.lbl_orphan_count = QLabel("0 encontrados")
        self.lbl_orphan_count.setObjectName("bundleInfo")
        orphan_head.addWidget(self.lbl_orphan_count)
        orphan_head.addStretch(1)
        orphan_head.addWidget(QLabel("Filtrar"))
        self.input_orphan_filter = QLineEdit()
        self.input_orphan_filter.setPlaceholderText("nombre app, carpeta, dominio...")
        self.input_orphan_filter.textChanged.connect(self._apply_orphan_filter)
        self.btn_clear_orphan_filter = QPushButton("Limpiar")
        self.btn_clear_orphan_filter.clicked.connect(self.input_orphan_filter.clear)
        orphan_head.addWidget(self.input_orphan_filter)
        orphan_head.addWidget(self.btn_clear_orphan_filter)

        self.list_orphans = QListWidget()
        self.list_orphans.setMaximumHeight(150)
        self.list_orphans.itemChanged.connect(self.handle_orphan_item_changed)
        self.list_orphans.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_orphans.customContextMenuRequested.connect(self._show_orphan_context_menu)

        orphan_actions = QHBoxLayout()
        self.btn_scan_orphans = QPushButton("Buscar restos")
        self.btn_scan_orphans.clicked.connect(self.handle_scan_orphans)
        self.btn_select_all_orphans = QPushButton("Seleccionar todos")
        self.btn_select_all_orphans.clicked.connect(self.select_all_orphans)
        self.btn_uninstall_orphans = QPushButton("Eliminar restos")
        self.btn_uninstall_orphans.clicked.connect(self.handle_uninstall_orphans)
        orphan_actions.addWidget(self.btn_scan_orphans)
        orphan_actions.addWidget(self.btn_select_all_orphans)
        orphan_actions.addStretch(1)
        orphan_actions.addWidget(self.btn_uninstall_orphans)

        orphan_layout.addLayout(orphan_head)
        orphan_layout.addWidget(self.list_orphans)
        orphan_layout.addLayout(orphan_actions)

        body.addLayout(head)
        body.addLayout(search)
        body.addLayout(center, 1)
        body.addLayout(action)
        body.addWidget(self._build_selection_footer())
        body.addWidget(orphan_card)
        return wrapper

    def _build_selection_footer(self) -> QWidget:
        footer = QFrame()
        footer.setObjectName("summaryBar")
        row = QHBoxLayout(footer)
        row.setContentsMargins(12, 10, 12, 10)
        row.setSpacing(18)

        self.lbl_selected_size = QLabel("0 B")
        self.lbl_selected_size.setObjectName("summaryValue")
        self.lbl_selected_count = QLabel("0")
        self.lbl_selected_count.setObjectName("summaryValue")

        left = QVBoxLayout()
        left.addWidget(QLabel("Selected Size"))
        left.addWidget(self.lbl_selected_size)

        right = QVBoxLayout()
        right.addWidget(QLabel("Selected Items"))
        right.addWidget(self.lbl_selected_count)

        row.addLayout(left)
        row.addLayout(right)
        row.addStretch(1)
        return footer

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: #0c2941; color: #d8ebff; }
            QLabel { color: #d8ebff; }
            QStatusBar { background: #082338; color: #9ec5e7; }
            QFrame#sidebar {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #071e31, stop:1 #04101a);
                border-right: 1px solid #103f61;
            }
            QLabel#sidebarTitle { font-size: 20px; font-weight: 700; color: #f7fbff; padding: 6px 4px; }
            QLabel#sidebarFooter { color: #5f92b8; padding-top: 10px; }
            QPushButton#sideNav {
                text-align: left; padding: 10px 12px; border-radius: 10px;
                border: 1px solid #1e4f72; background: #0a2d45; color: #b5d5f0;
            }
            QPushButton#sideNav:checked { background: #14507a; color: #ffffff; border-color: #2f89cc; }
            QLabel#mainTitle { font-size: 28px; font-weight: 700; color: #f2f8ff; }
            QLabel#mainSubtitle { font-size: 13px; color: #8bb7d9; }
            QLabel#bundleInfo { color: #85b0d2; font-size: 12px; padding: 0 0 4px 0; }
            QFrame#card { background: #0b3250; border: 1px solid #1d5a83; border-radius: 12px; }
            QFrame#summaryBar { background: #0a3858; border: 1px solid #20618b; border-radius: 12px; }
            QLabel#summaryValue { font-size: 30px; font-weight: 700; color: #f5fbff; }
            QLabel#selectionBadge {
                background: #d64155; color: #ffffff; border: 1px solid #f17788;
                border-radius: 11px; min-width: 22px; min-height: 22px; padding: 0 6px;
                font-weight: 700; qproperty-alignment: AlignCenter;
            }
            QListWidget, QTreeWidget, QLineEdit, QComboBox {
                background: #082b44; color: #e6f4ff; border: 1px solid #1f648f; border-radius: 8px;
            }
            QHeaderView::section {
                background: #12466a; color: #d9ecff; border: none; padding: 6px; font-weight: 600;
            }
            QPushButton {
                background: #12496f; color: #f1f7ff; border: 1px solid #2a6f9d;
                border-radius: 10px; padding: 7px 12px;
            }
            QPushButton:hover { background: #17608e; }
            QPushButton#primaryBtn { background: #1e82d1; border-color: #4ca5eb; font-weight: 700; padding: 8px 20px; }
            QPushButton#dangerBtn { background: #7a2435; border-color: #ab3b52; font-weight: 700; }
            QCheckBox { color: #cde7ff; }
            """
        )

    def load_installed_apps(self) -> None:
        current_text = self.input_name.currentText().strip()
        apps = list_installed_apps()

        self.input_name.blockSignals(True)
        self.input_name.clear()
        self.input_name.addItems(apps)
        self.widget_installed_apps.clear()
        self.widget_installed_apps.addItems(apps)
        if current_text:
            self.input_name.setEditText(current_text)
        self.input_name.blockSignals(False)

        self.statusBar().showMessage("Apps detectadas: {}".format(len(apps)))

    def handle_app_selected(self, list_item: QListWidgetItem) -> None:
        app_name = list_item.text()
        self.input_name.setEditText(app_name)
        self._run_deep_scan(app_name)

    def handle_scan(self) -> None:
        app_name = self.input_name.currentText().strip()
        if not app_name:
            QMessageBox.warning(self, "Falta nombre", "Ingresa el nombre de la app.")
            return
        self._run_deep_scan(app_name)

    def _run_deep_scan(self, app_name: str) -> None:
        if is_system_protected_app(app_name):
            msg = "⚠️ {} es una app del sistema protegida por SIP (System Integrity Protection).\n\n".format(app_name)
            msg += "No se puede eliminar la app principal sin deshabilitar SIP, pero sí se pueden limpiar datos de usuario.\n\n"
            msg += "¿Deseas continuar con la limpieza de datos de usuario?"
            dlg = QDialog(self)
            dlg.setWindowTitle("App del Sistema Protegida")
            dlg.resize(560, 280)
            _style_dialog(dlg)
            layout = QVBoxLayout(dlg)
            title_label = QLabel("⚠️ Limitación de macOS")
            title_label.setObjectName("dialogTitle")
            layout.addWidget(title_label)
            msg_label = QLabel(msg)
            msg_label.setWordWrap(True)
            layout.addWidget(msg_label)
            actions = QHBoxLayout()
            actions.addStretch(1)
            btn_cancel = QPushButton("Cancelar")
            btn_cancel.clicked.connect(dlg.reject)
            btn_ok = QPushButton("Limpiar datos")
            btn_ok.clicked.connect(dlg.accept)
            actions.addWidget(btn_cancel)
            actions.addWidget(btn_ok)
            layout.addLayout(actions)
            if dlg.exec_() != QDialog.Accepted:
                return

        self.statusBar().showMessage("Escaneando {}...".format(app_name))
        try:
            result = deep_scan_app(app_name)
        except Exception:
            _show_error_dialog(self, "Error en el escaneo", traceback.format_exc())
            self.statusBar().showMessage("Error durante el escaneo")
            return

        self.lbl_bundle_id.setText(
            "Bundle ID: {} ⚠️ SISTEMA (SIP protegido)".format(result.bundle_id) if (result.bundle_id and is_system_protected_app(app_name)) else ("Bundle ID: {}".format(result.bundle_id) if result.bundle_id else "Bundle ID: no detectado")
        )

        self.current_deep_items = result.items
        self.category_items = {}
        self.category_totals = {}
        self.checked_paths = {}

        for item in result.items:
            self.category_items.setdefault(item.category, []).append(item)
            self.checked_paths[str(item.path)] = True

        self.tree_categories.clear()
        bucket_nodes: Dict[str, QTreeWidgetItem] = {}
        for bucket in _BUCKET_ORDER:
            section = QTreeWidgetItem([bucket])
            section.setFlags(section.flags() & ~Qt.ItemIsSelectable)
            section.setExpanded(True)
            self.tree_categories.addTopLevelItem(section)
            bucket_nodes[bucket] = section

        ordered = sorted(
            self.category_items.items(),
            key=lambda x: sum(i.size_bytes for i in x[1]),
            reverse=True,
        )
        for category, items in ordered:
            total = sum(i.size_bytes for i in items)
            self.category_totals[category] = total
            bucket = _size_bucket(total)
            label = "[{}] {}  |  {} items  |  {}  | selected 0".format(
                bucket,
                category,
                len(items),
                _format_size(total),
            )
            node = QTreeWidgetItem([label])
            node.setData(0, Qt.UserRole, category)
            bucket_nodes[bucket].addChild(node)

        for i in range(self.tree_categories.topLevelItemCount() - 1, -1, -1):
            section = self.tree_categories.topLevelItem(i)
            if section.childCount() == 0:
                self.tree_categories.takeTopLevelItem(i)

        first_category_node = self._first_category_node()
        if first_category_node is not None:
            self.tree_categories.setCurrentItem(first_category_node)
            self.handle_category_selected(first_category_node)
        else:
            self.tree_results.clear()

        self._update_selection_footer()
        self._refresh_category_badges()

        total_size = sum(i.size_bytes for i in result.items)
        self.statusBar().showMessage(
            "{} elementos detectados, {} total".format(len(result.items), _format_size(total_size))
        )

    def handle_category_tree_clicked(self, tree_item: QTreeWidgetItem, _column: int) -> None:
        if not tree_item.data(0, Qt.UserRole):
            tree_item.setExpanded(not tree_item.isExpanded())
            return
        self.handle_category_selected(tree_item)

    def handle_category_selected(self, tree_item: QTreeWidgetItem) -> None:
        category = tree_item.data(0, Qt.UserRole)
        self.active_category = category
        self.tree_results.clear()

        items = sorted(
            self.category_items.get(category, []),
            key=lambda i: (_RISK_ORDER.get(i.risk_level, 99), str(i.path)),
        )
        for item in items:
            path_key = str(item.path)
            row = QTreeWidgetItem([
                "",
                path_key,
                _format_size(item.size_bytes),
                _RISK_LABELS.get(item.risk_level, ""),
                item.risk_reason,
            ])
            row.setData(0, Qt.UserRole, path_key)
            row.setCheckState(0, Qt.Checked if self.checked_paths.get(path_key, True) else Qt.Unchecked)
            row.setBackground(3, _RISK_BG.get(item.risk_level, QColor("#0b3250")))
            self.tree_results.addTopLevelItem(row)

    def handle_tree_item_clicked(self, tree_item: QTreeWidgetItem, _column: int) -> None:
        self.statusBar().showMessage(tree_item.text(4))

    def handle_tree_item_changed(self, tree_item: QTreeWidgetItem, _column: int) -> None:
        path_key = tree_item.data(0, Qt.UserRole)
        if not path_key:
            return
        self.checked_paths[path_key] = tree_item.checkState(0) == Qt.Checked
        self._update_selection_footer()
        self._refresh_category_badges()

    def select_all(self) -> None:
        for i in range(self.tree_results.topLevelItemCount()):
            row = self.tree_results.topLevelItem(i)
            row.setCheckState(0, Qt.Checked)
            self.checked_paths[row.data(0, Qt.UserRole)] = True
        self._update_selection_footer()
        self._refresh_category_badges()

    def select_high_risk_only(self) -> None:
        risky = {RiskLevel.HIGH, RiskLevel.CRITICAL}
        risky_paths = {str(i.path) for i in self.current_deep_items if i.risk_level in risky}
        for i in range(self.tree_results.topLevelItemCount()):
            row = self.tree_results.topLevelItem(i)
            path_key = row.data(0, Qt.UserRole)
            checked = path_key in risky_paths
            row.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)
            self.checked_paths[path_key] = checked
        self._update_selection_footer()
        self._refresh_category_badges()

    def handle_uninstall(self) -> None:
        selected: List[CandidatePath] = []
        for item in self.current_deep_items:
            path_key = str(item.path)
            if self.checked_paths.get(path_key, False):
                selected.append(CandidatePath(path=item.path, category=item.category))

        if not selected:
            _show_result_dialog(self, "Nada seleccionado", "No hay elementos seleccionados.")
            return

        confirm = _ask_confirm_dialog(
            self,
            "Confirmar eliminacion",
            "Se eliminaran {} rutas. Deseas continuar?".format(len(selected)),
        )
        if not confirm:
            return

        removed, errors, manifest = uninstall_paths(
            selected,
            permanent=self.chk_permanent.isChecked(),
        )
        summary = "Eliminados: {}\nManifiesto: {}".format(removed, manifest)
        detail = ""
        if errors:
            detail = "Errores:\n" + "\n".join(errors[:10])
        _show_result_dialog(self, "Resultado de desinstalacion", summary, detail)
        self.statusBar().showMessage("Proceso finalizado. Eliminados: {}".format(removed))

    def handle_fix_launch_services(self) -> None:
        self.statusBar().showMessage("Reconstruyendo LaunchServices...")
        try:
            msg = refresh_launch_services()
            _show_result_dialog(self, "LaunchServices", msg)
            self.statusBar().showMessage(msg)
        except Exception:
            _show_error_dialog(self, "Error LaunchServices", traceback.format_exc())

    def handle_scan_orphans(self) -> None:
        self.current_orphans = list_orphan_leftovers()
        self.checked_orphans = {}
        for orphan in self.current_orphans:
            self.checked_orphans[str(orphan.path)] = False
        self._apply_orphan_filter(self.input_orphan_filter.text())
        self.statusBar().showMessage("Restos huerfanos detectados: {}".format(len(self.current_orphans)))

    def _apply_orphan_filter(self, text: str) -> None:
        query = text.strip().lower()
        self.list_orphans.clear()
        visible_count = 0
        for orphan in self.current_orphans:
            label = "[{}] [{}] [{}] {}".format(
                orphan.app_name,
                orphan.category,
                _format_size(orphan.size_bytes),
                orphan.path,
            )
            if query and query not in label.lower():
                continue
            row = QListWidgetItem(label)
            row.setData(Qt.UserRole, str(orphan.path))
            row.setFlags(row.flags() | Qt.ItemIsUserCheckable)
            checked = self.checked_orphans.get(str(orphan.path), False)
            row.setCheckState(Qt.Checked if checked else Qt.Unchecked)
            self.list_orphans.addItem(row)
            visible_count += 1

        total_count = len(self.current_orphans)
        if query:
            self.lbl_orphan_count.setText("{} visibles de {}".format(visible_count, total_count))
        else:
            self.lbl_orphan_count.setText("{} encontrados".format(total_count))

    def handle_orphan_item_changed(self, list_item: QListWidgetItem) -> None:
        path_key = list_item.data(Qt.UserRole)
        if not path_key:
            return
        self.checked_orphans[path_key] = list_item.checkState() == Qt.Checked

    def _show_orphan_context_menu(self, pos) -> None:
        item = self.list_orphans.itemAt(pos)
        if not item:
            return
        path_key = item.data(Qt.UserRole)
        if not path_key:
            return

        menu = QMenu(self)
        act_finder = menu.addAction("Mostrar en Finder")
        action = menu.exec_(self.list_orphans.viewport().mapToGlobal(pos))
        if action == act_finder:
            subprocess.Popen(["open", "-R", path_key])

    def select_all_orphans(self) -> None:
        for i in range(self.list_orphans.count()):
            row = self.list_orphans.item(i)
            row.setCheckState(Qt.Checked)
            self.checked_orphans[row.data(Qt.UserRole)] = True

    def handle_uninstall_orphans(self) -> None:
        # Persist current visual checkbox state.
        for i in range(self.list_orphans.count()):
            row = self.list_orphans.item(i)
            self.checked_orphans[row.data(Qt.UserRole)] = row.checkState() == Qt.Checked

        selected: List[CandidatePath] = []
        for orphan in self.current_orphans:
            if self.checked_orphans.get(str(orphan.path), False):
                selected.append(CandidatePath(path=orphan.path, category=orphan.category))

        if not selected:
            _show_result_dialog(self, "Nada seleccionado", "No hay restos seleccionados.")
            return

        confirm = _ask_confirm_dialog(
            self,
            "Confirmar eliminacion",
            "Se eliminaran {} restos huerfanos. Deseas continuar?".format(len(selected)),
        )
        if not confirm:
            return

        removed, errors, manifest = uninstall_paths(
            selected,
            permanent=self.chk_permanent.isChecked(),
        )
        summary = "Restos eliminados: {}\nManifiesto: {}".format(removed, manifest)
        detail = ""
        if errors:
            detail = "Errores:\n" + "\n".join(errors[:10])
        _show_result_dialog(self, "Resultado de limpieza", summary, detail)
        self.statusBar().showMessage("Restos eliminados: {}".format(removed))
        self.handle_scan_orphans()

    def handle_reset(self) -> None:
        self.input_name.clearEditText()
        self.lbl_bundle_id.setText("Bundle ID: -")
        self.tree_categories.clear()
        self.tree_results.clear()
        self.current_deep_items = []
        self.category_items = {}
        self.category_totals = {}
        self.checked_paths = {}
        self.list_orphans.clear()
        self.current_orphans = []
        self.checked_orphans = {}
        self.input_orphan_filter.clear()
        self.lbl_orphan_count.setText("0 encontrados")
        self._update_selection_footer()
        self._refresh_category_badges()
        self.statusBar().showMessage("Interfaz reiniciada")

    def _update_selection_footer(self) -> None:
        selected = [
            item for item in self.current_deep_items if self.checked_paths.get(str(item.path), False)
        ]
        selected_size = sum(item.size_bytes for item in selected)
        selected_count = len(selected)
        self.lbl_selected_count.setText(str(selected_count))
        self.lbl_selected_size.setText(_format_size(selected_size))
        self.lbl_selection_badge.setText(str(selected_count))
        self.lbl_selection_badge.setVisible(selected_count > 0)
        if selected_count > 0:
            self.btn_uninstall.setText("Remove ({})".format(selected_count))
        else:
            self.btn_uninstall.setText("Remove")

    def _refresh_category_badges(self) -> None:
        for i in range(self.tree_categories.topLevelItemCount()):
            section = self.tree_categories.topLevelItem(i)
            for j in range(section.childCount()):
                node = section.child(j)
                category = node.data(0, Qt.UserRole)
                if not category:
                    continue
                items = self.category_items.get(category, [])
                total = self.category_totals.get(category, sum(x.size_bytes for x in items))
                selected_count = 0
                for item in items:
                    if self.checked_paths.get(str(item.path), False):
                        selected_count += 1
                node.setText(
                    0,
                    "[{}] {}  |  {} items  |  {}  | selected {}".format(
                        _size_bucket(total),
                        category,
                        len(items),
                        _format_size(total),
                        selected_count,
                    ),
                )

    def _first_category_node(self) -> QTreeWidgetItem:
        for i in range(self.tree_categories.topLevelItemCount()):
            section = self.tree_categories.topLevelItem(i)
            if section.childCount() > 0:
                return section.child(0)
        return None


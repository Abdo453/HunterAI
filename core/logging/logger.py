"""
نظام السجلات المنظم لـ HunterAI
يدعم السجلات الملونة للمحطة والملفات
"""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from core.config.settings import config


class HunterAIFormatter(logging.Formatter):
    """منسق سجلات مخصص مع ألوان للمحطة."""
    
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        color = self.COLORS.get(levelname, self.RESET)
        record.levelname = f"{color}{levelname}{self.RESET}"
        return super().format(record)


def setup_logger(
    name: str = "hunterai",
    level: Optional[int] = None,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    إعداد recorder لنظام HunterAI.
    
    Args:
        name: اسم הlogger
        level: مستوى السجل (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: مسار ملف السجل (اختياري)
    
    Returns:
        logging.Logger: الكائن المجهز
    """
    if level is None:
        level = logging.DEBUG if config.debug else logging.INFO

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []  # تنظيف السجلات السابقة

    # صيغة السجل
    formatter = HunterAIFormatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # سجل المحطة (Console)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # سجل الملف (اختياري)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


# مثيل عام للسجل
logger = setup_logger(
    name="hunterai",
    log_file="logs/hunterai.log",
)

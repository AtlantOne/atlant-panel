#!/usr/bin/python3 -I
"""Restricted root helper entry point, installed separately from the web service."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from control.service_helper import main

if __name__=='__main__':main()

#!/bin/env python
# -*- coding: utf-8 -*-
# Inspired by the code in http://www.copyandwaste.com/posts/view/multiprocessing-snmp-with-python/
__author__ = 'eduardo'
import netsnmp
import subprocess
import logging
import re

log = logging.getLogger()


class Host(object):
    """
    Creates a host record
    """

    def __init__(self,
                 hostname=None,
                 query=None):
        self.hostname = hostname
        self.query = query


class SnmpSession(object):
    """A SNMP Session"""
    def __init__(self,
                 oid=".1.3.6.1.2.1.1.1.0",
                 iid=None,
                 Version=2,
                 DestHost="localhost",
                 Community="public",
                 Verbose=True,
                 Timeout=1000000
                 ):
        """
        Sessão SNMP. Links úteis:
        Lista de MIB's para impressoras: http://www.lprng.com/DISTRIB/SNMPTOOLS/snmp_stuff/test_printer/npstatlib.pm
        Identificação de swicthes e roteadores: http://www.codeproject.com/Questions/642173/OIDs-for-Router-and-SWITCH-identification-using-SN

        :param oid: MIB SNMP
        :param iid: Não sei
        :param Version: Versão do protocolo
        :param DestHost: Endereço para consulta
        :param Community: Community para consulta
        :param Verbose: Verbose
        """
        self.oid = oid
        self.Version = Version
        self.DestHost = DestHost
        self.Community = Community
        self.Verbose = Verbose
        self.Timeout = Timeout
        self.var = netsnmp.Varbind(oid, iid)
        self.hostrec = Host()
        self.hostrec.hostname = self.DestHost

        self.status = ['.1.3.6.1.2.1.25.3.5.1.1.1']
        self.serial = ['.1.3.6.1.2.1.43.5.1.1.17',
                       '.1.3.6.1.2.1.43.5.1.1.17.1',
                       '.1.3.6.1.4.1.641.2.1.2.1.6.1',
                       '.1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0']
        self.model = ['.1.3.6.1.2.1.25.3.2.1.3.1',
                      '.1.3.6.1.4.1.641.2.1.2.1.2.1']
        self.counter = ['.1.3.6.1.2.1.43.10.2.1.4.1.1']
        self.messages = ['.1.3.6.1.2.1.43.18.1.1.8']
        self.ip_forwarding = ['.1.3.6.1.2.1.4.1']  # Retorna 1 se estiver fazendo IP Forwarding (router)
        self.bridge = ['.1.3.6.1.2.1.17']  # Retorna 1 se estiver fazendo bridge (switch)

        # Coletas SNMP para ativos de rede
        self.sys_up_time = ['.1.3.6.1.2.1.1.3.0']  # Uptime
        self.snmp_hostname = ['.1.3.6.1.2.1.1.5.0']  # Hostname
        self.version = [".1.3.6.1.2.1.1.1.0"]  # Descriçao completa, incluindo tipo de hardware e rede
        self.location = [".1.3.6.1.2.1.1.6.0"]  # Localização
        self.contact = [".1.3.6.1.2.1.1.4.0"]  # Contato do resposável pelo equipamento
        self.avg_busy1 = [".1.3.6.1.4.1.9.2.1.57.0"]  # Load Average último minuto
        self.avg_busy5 = [".1.3.6.1.4.1.9.2.1.58.0"]  # Load average últimos 5 minutos
        self.memory = [".1.3.6.1.4.1.9.3.6.6.0"]  # Utilização de CPU
        self.services = [".1.3.6.1.2.1.1.7.0"]  # Serviços oferecidos
        self.if_phys_address = [".1.3.6.1.2.1.2.2.1.6"]  # MAC Address

        # Atributos específicos para ativos CISCO
        self.chassis = ['.1.3.6.1.4.1.9.3.6.1.0']  # Chassis para a função get_chassis
        self.why_reload = [".1.3.6.1.4.1.9.2.1.2.0"]  # Motivo do último reinício
        self.sys_config_name = [".1.3.6.1.4.1.9.2.1.73.0"]  # CISCO - Nome da imagem de boot do dipositivo
        self.ts_lines = [".1.3.6.1.4.1.9.2.9.1.0"]  # Número de linhas do terminal
        self.cm_system_installed_modem = [".1.3.6.1.4.1.9.9.47.1.1.1.0"]  # Modems instalados em ativos CISCO
        self.cm_system_modems_in_use = [".1.3.6.1.4.1.9.9.47.1.1.6.0"]  # Modems em uso nos ativos CISCO
        self.cm_system_modems_dead = [".1.3.6.1.4.1.9.9.47.1.1.10.0"]  # Modems falhando em ativos CISCO

        # Definições genéricas de opções válidas no escopo do objeto
        self.service_options = {
            1: "repeater",
            2: "bridge",
            4: "router",
            6: "switch",
            8: "gateway",
            16: "session",
            32: "terminal",
            64: "application"
        }

        self.chassis_options = {
            1: "unknown",
            2: "multibus",
            3: "agsplus",
            4: "igs",
            5: "c2000",
            6: "c3000",
            7: "c4000",
            8: "c7000",
            9: "cs500",
            10: "c7010",
            11: "c2500",
            12: "c4500",
            13: "c2102",
            14: "c2202",
            15: "c2501",
            16: "c2502",
            17: "c2503",
            18: "c2504",
            19: "c2505",
            20: "c2506",
            21: "c2507",
            22: "c2508",
            23: "c2509",
            24: "c2510",
            25: "c2511",
            26: "c2512",
            27: "c2513",
            28: "c2514",
            29: "c2515",
            30: "c3101",
            31: "c3102",
            32: "c3103",
            33: "c3104",
            34: "c3202",
            35: "c3204",
            36: "accessProRC",
            37: "accessProEC",
            38: "c1000",
            39: "c1003",
            40: "c1004",
            41: "c2516",
            42: "c7507",
            43: "c7513",
            44: "c7506",
            45: "c7505",
            46: "c1005",
            47: "c4700",
            48: "c2517",
            49: "c2518",
            50: "c2519",
            51: "c2520",
            52: "c2521",
            53: "c2522",
            54: "c2523",
            55: "c2524",
            56: "c2525",
            57: "c4700S",
            58: "c7206",
            59: "c3640",
            60: "as5200",
            61: "c1601",
            62: "c1602",
            63: "c1603",
            64: "c1604",
            65: "c7204",
            66: "c3620",
            68: "wsx3011",
            69: "mc3810",
            72: "c1503",
            73: "as5300",
            74: "as2509RJ",
            75: "as2511RJ",
            77: "c2501FRADFX",
            78: "c2501LANFRADFX",
            79: "c2502LANFRADFX",
            80: "wsx5302",
            81: "c1605",
            82: "c12012",
            85: "c12008",
            86: "ubr7246",
            87: "c2610",
            88: "c2612",
            89: "c2611",
            90: "ubr904",
            91: "c6200",
            92: "c3660",
            94: "c7202",
            95: "c2620",
            96: "c2621",
            99: "rpm",
            100: "c1710",
            101: "c1720",
            102: "c7576",
            103: "c1401",
            104: "c2613",
            105: "ubr7223",
            106: "c6400Nrp",
            107: "c801",
            108: "c802",
            109: "c803",
            110: "c804",
            111: "c7206VXR",
            112: "c7204VXR",
            113: "c1750",
            114: "mgx8850",
            116: "c805",
            117: "ws-c3508g-xl",
            118: "ws-c3512-xl",
            119: "ws-c3524-xl",
            120: "ws-c2908-xl",
            121: "ws-c2916m-xl",
            122: "ws-c2924-xl-v",
            123: "ws-c2924c-xl-v",
            124: "ws-c2912-xl",
            125: "ws-c2924m-xl",
            126: "ws-c2912mf-xl",
            128: "c1417",
            129: "cOpticalRegenerator",
            130: "ws-c2924-xl",
            131: "ws-c2924c-xl",
            132: "ubr924",
            133: "ws-x6302-msm",
            134: "cat5k-rsfc",
            136: "c7120-quadt1",
            137: "c7120-t3",
            138: "c7120-e3",
            139: "c7120-at3",
            140: "c7120-ae3",
            141: "c7120-smi3",
            142: "c7140-dualt3",
            143: "c7140-duale3",
            144: "c7140-dualat3",
            145: "c7140-dualae3",
            146: "c7140-dualmm3",
            148: "ubr-7246-vxr",
            150: "c12016",
            151: "as5400",
            152: "c7140-octt1",
            153: "c7140-dualfe",
            154: "cat3548xl",
            155: "cat6006",
            156: "cat6009",
            157: "cat6506",
            158: "cat6509",
            160: "mc3810-v3",
            162: "c7507z",
            163: "c7513z",
            164: "c7507mx",
            165: "c7513mx",
            166: "ubr912-c",
            167: "ubr912-s",
            168: "ubr914",
            171: "c6160",
            173: "cat4232-l3",
            174: "cOpticalRegeneratorDCPower",
            180: "cva122",
            181: "cva124",
            182: "as5850",
            185: "mgx8240",
            191: "ubr925",
            192: "ubr10012",
            194: "c12016-8r",
            195: "c2650",
            196: "c2651",
            202: "c1751",
            205: "c626",
            206: "c627",
            207: "c633",
            208: "c673",
            209: "c675",
            210: "c675e",
            211: "c676",
            212: "c677",
            213: "c678",
            214: "c3661-ac",
            215: "c3661-dc",
            216: "c3662-ac",
            217: "c3662-dc",
            218: "c3662-ac-co",
            219: "c3662-dc-co",
            220: "ubr7111",
            222: "ubr7114",
            224: "c12010",
            225: "c8110",
            227: "ubr905",
            231: "c7150-dualfe",
            232: "c7150-octt1",
            233: "c7150-dualt3",
            236: "cvps1110",
            237: "ccontentengine",
            238: "ciad2420",
            239: "c677i",
            240: "c674",
            241: "cdpa7630",
            242: "cat355024",
            243: "cat355048",
            244: "cat355012t",
            245: "cat2924-lre-xl",
            246: "cat2912-lre-xl",
            247: "cva122e",
            248: "cva124e",
            249: "curm",
            250: "curm2fe",
            251: "curm2fe2v",
            252: "c7401VXR",
            255: "cap340",
            256: "cap350",
            257: "cdpa7610",
            261: "c12416",
            262: "ws-c2948g-l3-dc",
            263: "ws-c4908g-l3-dc",
            264: "c12406",
            265: "pix-firewall506",
            266: "pix-firewall515",
            267: "pix-firewall520",
            268: "pix-firewall525",
            269: "pix-firewall535",
            270: "c12410",
            271: "c811",
            272: "c813",
            273: "c10720",
            274: "cMWR1900",
            275: "c4224",
            276: "cWSC6513",
            277: "c7603",
            278: "c7606",
            279: "c7401ASR",
            280: "cVG248",
            281: "c1105",
            284: "cCe507",
            285: "cCe560",
            286: "cCe590",
            287: "cCe7320",
            288: "c2691",
            289: "c3725",
            291: "c1760",
            292: "pix-firewall501",
            293: "c2610M",
            294: "c2611M",
            298: "c12404",
            299: "c9004",
            306: "cat355012g",
            307: "cCe507av",
            308: "cCe560av",
            309: "cIe2105",
            311: "c10005",
            312: "c10008",
            313: "c7304",
            322: "cWSC6503",
            323: "pix-firewall506e",
            324: "pix-firewall515e",
            325: "cat355024-dc",
            326: "ccontentengine2636",
            327: "ccontentengine-dw2636",
            329: "mgx-14-8830",
            332: "c6400-uac",
            334: "c2610XM",
            335: "c2611XM",
            336: "c2620XM",
            337: "c2621XM",
            338: "c2650XM",
            339: "c2651XM",
            344: "c12816",
            345: "c12810",
            350: "cat295024sx",
            351: "cat2955-t12",
            352: "cat2955-c12",
            353: "as5400-hpx",
            354: "as5350-hpx",
            362: "airap-1100",
            364: "cat2955-s12",
            365: "c7609",
            371: "cMWR1941DC",
            372: "cVG200",
            373: "airap1210",
            374: "cat375048PS",
            375: "cat375024PS",
            376: "cat297024",
            377: "c7613",
            379: "cat3750-12ge-sfp",
            380: "airbr-1410",
            381: "cWSC6509neba",
            382: "c1711",
            383: "c1712",
            384: "c1701",
            385: "cat29408TT",
            386: "cat29408TF",
            389: "c2430iad-24fxs",
            390: "c2431iad-8fxs",
            391: "c2431iad-16fxs",
            392: "c2431iad-1t1e1",
            393: "c2432iad-24fxs",
            394: "airap350ios",
            396: "cat295024-lre-st-997",
            397: "cVG224",
            398: "cat295048t",
            399: "cat295048sx",
            400: "cat6k-sup720",
            401: "cat297024-ts",
            402: "cat356048-ps",
            403: "cat356024-ps",
            404: "airbr-1300",
            410: "c878",
            411: "c871",
            413: "c2811",
            414: "c2821",
            415: "c2851",
            416: "cat375024-me",
            420: "cat3750g-16td",
            422: "cigesm",
            423: "c1841",
            424: "c2801",
            426: "cat3750G24-ps",
            427: "cat3750G48-ps",
            428: "cat3750G48-ts",
            430: "cds-x9132-k9",
            431: "cds-x9116-k9",
            432: "cat3560G24-ps",
            433: "cat3560G24-ts",
            434: "cat3560G48-ps",
            435: "cat3560G48-ts",
            436: "cds-c9216i-k9",
            437: "as5400-xm",
            438: "as5350-xm",
            439: "airap-1130",
            440: "c7604",
            441: "cat3750G24-ts1u",
            442: "cn7kc7010",
            443: "c371098-hp-001",
            447: "cat356024-ts",
            448: "cat356048-ts",
            454: "cwlse1130",
            455: "cwlse1030",
            457: "cids4210",
            458: "cids4215",
            459: "cids4235",
            460: "cids4240",
            461: "cids4250",
            462: "cids4250sx",
            463: "cids4250xl",
            464: "cids4255",
            465: "cat375024-fs",
            466: "cWSC6504E",
            467: "cigesm-sfp",
            468: "cfe-6326-k9",
            471: "dsC9120ClK9",
            476: "cat3750-ge12-sfp-dc",
            477: "cat296024",
            478: "cat296048",
            479: "cat2960-g24",
            480: "cat2960-g48",
            481: "cat6k-msfc2a",
            482: "cme6340aca",
            483: "cme6340dca",
            484: "cme6340dcb",
            485: "cat296024-tt",
            486: "cat296048-tt",
            487: "cige-sms-sfp-t",
            488: "cMEC6524gs8s",
            489: "cMEC6524gt8s",
            492: "cPaldron",
            493: "nm-16es-1ge",
            494: "nm-x-24es-1ge",
            495: "nm-xd-24es-2st",
            496: "nm-xd-48es-2ge",
            497: "nm-16es-1ge-no-pwr",
            498: "nm-xd-24es-2st-no-pwr",
            499: "nm-xd-48es-2ge-no-pwr",
            500: "nm-x-24es-1ge-no-pwr",
            501: "cigesm-t",
            502: "catCE500-24tt",
            503: "catCE500-24lc",
            504: "catCE500-24pc",
            505: "catCE500-12tc",
            506: "c5750",
            507: "cMWR1941DCA",
            508: "c815",
            509: "c240024-tsa",
            510: "c240024-tsd",
            511: "c340024-tsa",
            512: "c340024-tsd",
            513: "cCRS18-linecard",
            514: "cCRS1-fabric",
            515: "cids4220",
            516: "cids4230",
            518: "ws-3020-hpq",
            519: "ws-3030-del",
            520: "cwlse-1133",
            521: "airap-1250",
            523: "cat3750-g24-ws",
            524: "me-3400g-12cs-a",
            525: "me-3400g-12cs-d",
            526: "c877-m",
            527: "c1801-m",
            528: "ws-cbs3040-fsc",
            529: "spa-ipsec-2g-2",
            530: "cDSC9124",
            531: "cat3750e-48-td",
            532: "cat3750e-24-td",
            533: "cat3750e-24-pd",
            534: "cat3750e-48-pd",
            535: "cat3560e-24-td",
            536: "cat3560e-48-td",
            537: "cat3560e-24-pd",
            538: "cat3560e-48-pd",
            539: "cat3560-8pc",
            540: "cat2960-8tc",
            541: "cat2960-g8-tc",
            542: "cDSIBMFC",
            543: "cips-virtual",
            544: "c5720",
            545: "cDSHPFC",
            546: "c3205WMIC",
            547: "me-3400g-2cs-a",
            548: "c7201",
            549: "ds-c9222i-k9",
            550: "cUBR-7225-vxr",
            552: "cWSC6509ve",
            553: "cDSC9134",
            557: "c5740",
            586: "c7816-h",
            587: "c7603s",
            588: "c7606s",
            589: "c7609s",
            590: "cmds-dsc-9222i",
            591: "cuc500",
            592: "c860-ap",
            593: "c880-ap",
            594: "c890-ap",
            595: "c1900-ap",
            596: "me-3400-24fs-a",
            597: "cuc520s-8u-4fxo-k9",
            598: "cuc520s-8u-4fxo-w-k9",
            599: "cuc520s-8u-2bri-k9",
            600: "cuc520s-8u-2bri-w-k9",
            601: "cuc520s-16u-4fxo-k9",
            602: "cuc520s-16u-4fxo-w-k9",
            603: "cuc520s-16u-2bri-k9",
            604: "cuc520s-16u-2bri-w-k9",
            605: "cuc520m-32u-8fxo-k9",
            606: "cuc520m-32u-8fxo-w-k9",
            607: "cuc520m-32u-4bri-k9",
            608: "cuc520m-32u-4bri-w-k9",
            609: "cuc520m-48u-12fxo-k9",
            610: "cuc520m-48u-12fxo-w-k9",
            611: "cuc520m-48u-6bri-k9",
            612: "cuc520m-48u-6bri-w-k9",
            613: "cuc520m-48u-1t1e1-f-k9",
            614: "cuc520m-48u-1t1e1-b-k9",
            615: "c7828-h",
            616: "c7816-i",
            617: "c7828-i",
            618: "c1861-uc-2b-k9",
            619: "c1861-uc-4f-k9",
            620: "c1861-srst-2b-k9",
            621: "c1861-srst-4f-k9",
            622: "c7330-oe-k9",
            623: "c7350-oe-k9",
            628: "cat2960-48tc-s",
            629: "cat2960-24tc-s",
            630: "cat2960-24-s",
            631: "cat2960-24pc-l",
            632: "cat2960-24lt-l",
            633: "cat2960pd-8tt-l",
            634: "casr1002",
            635: "casr1004",
            636: "casr1006",
            637: "catrfgw",
            638: "catce520-24pc",
            639: "catce520-24lc",
            640: "catce520-24tt",
            641: "catce520-g24tc",
            642: "c1861-srst-2b-cue-k9",
            643: "c1861-srst-4f-cue-k9",
            644: "cvgd-1t3",
            648: "ws-cbs3130g-s",
            649: "ws-cbs3130x-s",
            650: "cat3560e-12-sd",
            651: "ccisco-optimization-engine-674",
            652: "cie3000-4tc",
            653: "cie3000-8tc",
            654: "craie1783-ms06",
            655: "craie1783-ms10t",
            656: "c2435iad-8fxs",
            657: "vg204",
            658: "vg202",
            659: "cat2918-24tt",
            660: "cat2918-24tc",
            661: "cat2918-48tt",
            662: "cat2918-48tc",
            663: "cuc520-24u-4bri-k9",
            664: "cuc520-24u-8fxo-k9",
            665: "cuc520s-8u-2bri-w-j-k9",
            666: "cuc520s-16u-2bri-w-j-k9",
            667: "c1805",
            669: "cmwr-2941-dc",
            670: "coe574",
            671: "coe474",
            672: "coe274",
            673: "c7816c",
            674: "cap801agn",
            675: "cap801gn",
            676: "c1861W-srst-4f-cue-k9",
            677: "c1861W-srst-2b-cue-k9",
            678: "c1861W-srst-4f-k9",
            679: "c1861W-srst-2b-k9",
            680: "c1861W-uc-4f-k9",
            681: "c1861W-uc-2b-k9",
            682: "cme-3400e-24ts-m",
            683: "cme-3400eg-12cs-m",
            684: "cme-3400eg-2cs-a",
            685: "cce674",
            686: "ccam35",
            692: "cce7341",
            693: "cce7371",
            694: "cat2960-48tts",
            695: "cat2960-8tcs",
            697: "sr520fe",
            698: "sr520adsl",
            699: "sr520adsli",
            700: "cn7kc7018",
            702: "cat3560-12pcs",
            703: "cat2960-48pstl",
            704: "cat3560v2-24ts-d",
            705: "cat3560v2-24ts",
            706: "cat3560v2-24ps",
            707: "cat3750v2-24ts",
            708: "cat3750v2-24ps",
            709: "cat3560v2-48ts",
            710: "cat3560v2-48ps",
            711: "cat3750v2-48ts",
            712: "cat3750v2-48ps",
            713: "airbr-1430",
            714: "namapp2204-rj45",
            715: "namapp2220",
            716: "airap-1141",
            717: "airap-1142",
            718: "c887-vdsl2",
            719: "c1941",
            720: "c2901",
            721: "c2911",
            722: "c2921",
            723: "c2951",
            724: "c3925",
            725: "c3945",
            726: "csr520-t1",
            728: "nam-app2204-sfp",
            741: "c3845nv",
            742: "c3825nv",
            743: "ws-c2350-48td",
            751: "casr1002f",
            760: "cdscde200",
            761: "cdscde100",
            762: "cdscde300",
            763: "cdscde400",
            767: "catsps-2004-b",
            768: "catsps-204-b",
            772: "cap541n-a-k9",
            773: "cap541n-e-k9",
            774: "cap541n-n-k9",
            775: "csrp521",
            776: "csrp526",
            777: "csrp527",
            778: "csrp541",
            779: "csrp546",
            780: "csrp547",
            781: "cvs510-fxo",
            782: "c887-gvdsl2",
            783: "c887-srstvdsl2",
            786: "c59xx",
            787: "cat2960-24-lcs",
            788: "cat2960-24-pcs",
            789: "cat2960-48-psts",
            790: "cnm-wae-900",
            791: "cnm-wae-700",
            793: "cn4kibmeth",
            796: "craie1783-rms06t",
            797: "craie1783-rms10t",
            798: "cesw-540-8p-k9",
            799: "cesw-520-8p-k9",
            815: "cn7kc7009",
            816: "cn4kibm-cisco-eth",
            817: "cmwr-2941-dca",
            832: "c1841ck9",
            833: "c2801ck9",
            834: "c2811ck9",
            835: "c2821ck9",
            837: "c3825ck9",
            838: "c3845ck9",
            859: "c1906ck9"
        }

    def query(self):
        """Creates SNMP query

        Fills out a Host Object and returns result
        """
        try:
            result = netsnmp.snmpget(self.var,
                                Version=self.Version,
                                DestHost=self.DestHost,
                                Community=self.Community,
                                Timeout=int(self.Timeout))
            self.hostrec.query = result
        except Exception, err:
            if self.Verbose:
                print err
            self.hostrec.query = None
        finally:
            return self.hostrec

    def printer_full(self):
        """
        Retorna status full da impressora, com todos os atributos
        """
        status = self.query()

        if status.query is not None:
            for response in status.query:
                if response is not None:
                    return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_status(self):
        """
        Retorna status da impressora

        Opções de status:

         1 - unknown
         2 - runnning
         3 - warning
         4 - testing
         5 - down
        """
        for elm in self.status:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_counter(self):
        """
        Retorna contador da impressora
        """
        for elm in self.counter:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_model(self):
        """
        Retorna contador da impressora
        """
        for elm in self.model:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_serial(self):
        """
        Retorna contador da impressora
        """
        for elm in self.serial:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def printer_dict(self):
        """
        Retorna o status de todos os atributos em um dicionário
        """
        full = self.printer_full()
        serial = self.printer_serial()
        model = self.printer_model()
        counter = self.printer_counter()
        status = self.printer_status()

        return_dict = {
            'description': full,
            'serial': serial,
            'model': model,
            'counter': counter,
            'status': status,
            'network_ip': self.DestHost
        }

        log.debug("COLETA DE IMPRESSORAS CONCLUÍDA!!! Retornando dicionário de informações")
        log.debug(return_dict)

        return return_dict

    def get_snmp_attribute(self, attribute):
        """
        Runs SNMP query and return first response

        :param attribute: Attribute to SNMP search
        :return: String returned or None
        """
        # Faz a busca SNMP pelo objeto
        search = getattr(self, attribute)
        if search is None:
            log.error("SNMP Session - Attribute %s not defined", attribute)
            return None

        for elm in search:
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            # A primeira vez que conseguir retornar um status, para
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        return response

        # Se chegou até aqui não encontrou nenhum resultado
        return None

    def identify_host(self):
        """
        Identifica o ativo de rede de acordo com o tipo de serviço fornecido.
        Parâmetro sysServices do SNMP.

        Fonte: http://www.alvestrand.no/objectid/1.3.6.1.2.1.1.7.html
        """

        service = self.get_snmp_attribute(self.services)

        if service is None:
            return None

        # Tudo o que for maior que 64 representa um computador que não será coletado via SNMP
        if int(service) > 64:
            return "application"

        return self.service_options.get(service)

    def get_chassis(self):
        """
        The serial number of the chassis. This MIB object will return the chassis serial number for any
        chassis that either a numeric or an alphanumeric serial number is being used.

        Fonte: http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?local=en&translate=Translate&objectInput=1.3.6.1.4.1.9.5.1.2.19

        Número de série do ativo de rede

        :return: String que descreve o tipo de ativo
        """
        response = self.get_snmp_attribute("chassis")
        if response is not None:
            # Busca elemento no dicionário de respostas
            return self.chassis_options.get(response)
        else:
            # Retorna vazio para atributo não encontrado
            return None


class NmapSession(object):
    """
    Realiza busca Nmap num ativo de rede
    Inspirado em https://github.com/c0r3dump3d/pylanos
    """
    def __init__(self,
                 host,
                 full=False,
                 outfile=None
                 ):
        """
        Parâmetros obrigatórios
        """
        self.host = host
        self.full = full
        if outfile is not None:
            self.outfile = outfile
        else:
            self.outfile = str(self.host).replace("/", "-") + ".xml"

    def scan(self):
        """
        Realiza busca Nmap
        :return:
        """
        try:
            if self.full:
                scanv = subprocess.Popen(["sudo",
                                          "nmap",
                                          "-PR",
                                          "-O",
                                          str(self.host),
                                          "-oX",
                                          self.outfile],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE).communicate()[0]
            else:
                scanv = subprocess.Popen(["sudo",
                                          "nmap",
                                          "-PE",
                                          "-PP",
                                          "-PS21,22,23,25,80,443,631,3306,3389,8080,9100",
                                          "-O",
                                          str(self.host),
                                          "-oX",
                                          self.outfile],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE).communicate()[0]
        except OSError:
            log.error("Install nmap: sudo apt-get install nmap")
            return False

        return True


class ArpSession(object):
    """
    Classe para buscar informações de MAC do ativo
    """
    def __init__(self,
                 host,
                 iface='eth0',
                 timeout='10'):
        """
        :param host: Endereço IP do host a ser escaneado
        :param mac: MAC address do host
        :param timeout: Timeout esperando pelo reply da interface
        """
        self.host = host
        self.iface = iface
        self.timeout = timeout

    def scan(self):
        """
        :return: Somente MAc
        """
        log.debug("Iniciando scan para o host %s", self.host)
        try:
            scanv = subprocess.Popen(["sudo",
                                      "arping",
                                      "-I",
                                      self.iface,
                                      "-c",
                                      '1',
                                      "-w",
                                      str(self.timeout),
                                      self.host],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE).communicate()[0]

            match = re.search("(\[)(.*)(\])", scanv)

            if match:
                return match.group(2)
            else:
                return None

        except OSError:
            log.error("Install arping: sudo apt-get install arping")
            return None

    def scan_list(self):
        """

        :return: List com host e MAC
        """
        log.debug("Iniciando scan para o host %s", self.host)
        try:
            scanv = subprocess.Popen(["sudo",
                                      "arping",
                                      "-I",
                                      self.iface,
                                      "-c",
                                      '1',
                                      "-w",
                                      self.timeout,
                                      self.host],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE).communicate()[0]

            match = re.search("(\[)(.*)(\])", scanv)

            if match:
                return [self.host, match.group(2)]

            return [self.host, match]
        except OSError:
            log.error("Install arping: sudo apt-get install arping")
            return None

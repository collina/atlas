import logging
import logging.config
import os

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(message)s"
    }
    },
    
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "simple",
            "stream": "ext://sys.stdout"
        },
        
        "info_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO",
            "formatter": "simple",
            "filename": "info.log",
            "maxBytes": "10485760",
            "backupCount": "20",
            "encoding": "utf8"
        },
        
        "error_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "simple",
            "filename": "errors.log",
            "maxBytes": "10485760",
            "backupCount": "20",
            "encoding": "utf8"
    }
    },
    
    "loggers": {
        "my_module": {
            "level": "ERROR",
            "handlers": ["console"],
            "propagate": "no"
    }
    },
    
    "root": {
        "level": "INFO",
        "handlers": ["console", "info_file_handler", "error_file_handler"]
}
}



logging.config.dictConfig(logging_config)

logger = logging.getLogger('Cartographer')

active_probes_url = "https://atlas.ripe.net/contrib/active_probes.json"
country_list = {'BD': 'Bangladesh', 'WF': 'Wallis and Futuna', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados', 'BE': 'Belgium', 'BL': 'Saint Barth\xc3\xa9lemy', 'BM': 'Bermuda', 'BN': 'Brunei Darussalam', 'BO': 'Bolivia, Plurinational State of', 'BH': 'Bahrain', 'BI': 'Burundi', 'BJ': 'Benin', 'BT': 'Bhutan', 'JM': 'Jamaica', 'BV': 'Bouvet Island', 'JO': 'Jordan', 'WS': 'Samoa', 'BQ': 'Bonaire, Sint Eustatius and Saba', 'BR': 'Brazil', 'BS': 'Bahamas', 'JE': 'Jersey', 'BY': 'Belarus', 'BZ': 'Belize', 'RU': 'Russian Federation', 'RW': 'Rwanda', 'RS': 'Serbia', 'LT': 'Lithuania', 'RE': 'R\xc3\xa9union', 'LU': 'Luxembourg', 'TJ': 'Tajikistan', 'RO': 'Romania', 'TK': 'Tokelau', 'GW': 'Guinea-Bissau', 'GU': 'Guam', 'GT': 'Guatemala', 'GS': 'South Georgia and the South Sandwich Islands', 'GR': 'Greece', 'GQ': 'Equatorial Guinea', 'GP': 'Guadeloupe', 'JP': 'Japan', 'GY': 'Guyana', 'GG': 'Guernsey', 'GF': 'French Guiana', 'GE': 'Georgia', 'GD': 'Grenada', 'GB': 'United Kingdom', 'UK': 'United Kingdom', 'GA': 'Gabon', 'GN': 'Guinea', 'GM': 'Gambia', 'GL': 'Greenland', 'GI': 'Gibraltar', 'GH': 'Ghana', 'OM': 'Oman', 'TN': 'Tunisia', 'BW': 'Botswana', 'HR': 'Croatia', 'HT': 'Haiti', 'HU': 'Hungary', 'HK': 'Hong Kong', 'HN': 'Honduras', 'HM': 'Heard Island and McDonald Islands', 'VE': 'Venezuela, Bolivarian Republic of', 'PR': 'Puerto Rico', 'PS': 'Palestine, State of', 'PW': 'Palau', 'PT': 'Portugal', 'SJ': 'Svalbard and Jan Mayen', 'PY': 'Paraguay', 'IQ': 'Iraq', 'PA': 'Panama', 'PF': 'French Polynesia', 'PG': 'Papua New Guinea', 'PE': 'Peru', 'PK': 'Pakistan', 'PH': 'Philippines', 'PN': 'Pitcairn', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon', 'ZM': 'Zambia', 'EH': 'Western Sahara', 'EE': 'Estonia', 'NA': 'Namibia', 'EG': 'Egypt', 'ZA': 'South Africa', 'EC': 'Ecuador', 'AL': 'Albania', 'VN': 'Viet Nam', 'KZ': 'Kazakhstan', 'ET': 'Ethiopia', 'ZW': 'Zimbabwe', 'SA': 'Saudi Arabia', 'ES': 'Spain', 'ER': 'Eritrea', 'ME': 'Montenegro', 'MD': 'Moldova, Republic of', 'MG': 'Madagascar', 'MF': 'Saint Martin (French part)', 'MA': 'Morocco', 'MC': 'Monaco', 'UZ': 'Uzbekistan', 'MM': 'Myanmar', 'ML': 'Mali', 'MO': 'Macao', 'MN': 'Mongolia', 'MH': 'Marshall Islands', 'US': 'United States', 'UM': 'United States Minor Outlying Islands', 'MT': 'Malta', 'MW': 'Malawi', 'MV': 'Maldives', 'MQ': 'Martinique', 'MP': 'Northern Mariana Islands', 'MS': 'Montserrat', 'MR': 'Mauritania', 'AG': 'Antigua and Barbuda', 'IM': 'Isle of Man', 'UG': 'Uganda', 'TZ': 'Tanzania, United Republic of', 'MY': 'Malaysia', 'MX': 'Mexico', 'IL': 'Israel', 'FR': 'France', 'IO': 'British Indian Ocean Territory', 'SX': 'Sint Maarten (Dutch part)', 'SH': 'Saint Helena, Ascension and Tristan da Cunha', 'FI': 'Finland', 'FJ': 'Fiji', 'FK': 'Falkland Islands (Malvinas)', 'FM': 'Micronesia, Federated States of', 'FO': 'Faroe Islands', 'NI': 'Nicaragua', 'NL': 'Netherlands', 'NO': 'Norway', 'SO': 'Somalia', 'NC': 'New Caledonia', 'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NZ': 'New Zealand', 'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'CK': 'Cook Islands', 'CI': "C\xc3\xb4te d'Ivoire", 'CH': 'Switzerland', 'CO': 'Colombia', 'CN': 'China', 'CM': 'Cameroon', 'CL': 'Chile', 'CC': 'Cocos (Keeling) Islands', 'CA': 'Canada', 'CG': 'Congo', 'CF': 'Central African Republic', 'CD': 'Congo, the Democratic Republic of the', 'CZ': 'Czech Republic', 'CY': 'Cyprus', 'CX': 'Christmas Island', 'CR': 'Costa Rica', 'CW': 'Cura\xc3\xa7ao', 'CV': 'Cape Verde', 'CU': 'Cuba', 'SZ': 'Swaziland', 'SY': 'Syrian Arab Republic', 'Code': 'Country name', 'KG': 'Kyrgyzstan', 'KE': 'Kenya', 'SS': 'South Sudan', 'SR': 'Suriname', 'KI': 'Kiribati', 'KH': 'Cambodia', 'SV': 'El Salvador', 'KM': 'Comoros', 'ST': 'Sao Tome and Principe', 'SK': 'Slovakia', 'KR': 'Korea, Republic of', 'SI': 'Slovenia', 'KP': "Korea, Democratic People's Republic of", 'KW': 'Kuwait', 'SN': 'Senegal', 'SM': 'San Marino', 'SL': 'Sierra Leone', 'SC': 'Seychelles', 'SB': 'Solomon Islands', 'KY': 'Cayman Islands', 'SG': 'Singapore', 'SE': 'Sweden', 'SD': 'Sudan', 'DO': 'Dominican Republic', 'DM': 'Dominica', 'DJ': 'Djibouti', 'DK': 'Denmark', 'VG': 'Virgin Islands, British', 'DE': 'Germany', 'YE': 'Yemen', 'AT': 'Austria', 'DZ': 'Algeria', 'MK': 'Macedonia, the former Yugoslav Republic of', 'UY': 'Uruguay', 'YT': 'Mayotte', 'MU': 'Mauritius', 'KN': 'Saint Kitts and Nevis', 'LB': 'Lebanon', 'LC': 'Saint Lucia', 'LA': "Lao People's Democratic Republic", 'TV': 'Tuvalu', 'TW': 'Taiwan, Province of China', 'TT': 'Trinidad and Tobago', 'TR': 'Turkey', 'LK': 'Sri Lanka', 'LI': 'Liechtenstein', 'LV': 'Latvia', 'TO': 'Tonga', 'TL': 'Timor-Leste', 'TM': 'Turkmenistan', 'LR': 'Liberia', 'LS': 'Lesotho', 'TH': 'Thailand', 'TF': 'French Southern Territories', 'TG': 'Togo', 'TD': 'Chad', 'TC': 'Turks and Caicos Islands', 'LY': 'Libya', 'VA': 'Holy See (Vatican City State)', 'VC': 'Saint Vincent and the Grenadines', 'AE': 'United Arab Emirates', 'AD': 'Andorra', '(.uk)': 'ISO 3166-2:GB', 'AF': 'Afghanistan', 'AI': 'Anguilla', 'VI': 'Virgin Islands, U.S.', 'IS': 'Iceland', 'IR': 'Iran, Islamic Republic of', 'AM': 'Armenia', 'IT': 'Italy', 'AO': 'Angola', 'AQ': 'Antarctica', 'AS': 'American Samoa', 'AR': 'Argentina', 'AU': 'Australia', 'VU': 'Vanuatu', 'AW': 'Aruba', 'IN': 'India', 'AX': '\xc3\x85land Islands', 'AZ': 'Azerbaijan', 'IE': 'Ireland', 'ID': 'Indonesia', 'UA': 'Ukraine', 'QA': 'Qatar', 'MZ': 'Mozambique'}

class definitions():
    pass
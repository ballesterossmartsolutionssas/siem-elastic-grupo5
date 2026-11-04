"""Genera kibana/dashboards/siem-dashboards.ndjson: dashboards ejecutivo (R8.6) y operacional (R8.7).

Los dashboards son código: se editan aquí, se regenera el ndjson y kibana-setup los importa al arrancar.
    python kibana/construir_dashboards.py
Para cargarlos sin reiniciar:  docker compose run --rm --no-deps kibana-setup
"""
import json
from pathlib import Path

DV_LOGS, DV_ALERTAS, DV_ERRORES = "logs-siem", "siem-alertas", "logs-siem-errores"
HOY = '@timestamp >= "now/d"'
SOSPECHOSO = ('(event.dataset : "siem.auth" and event.outcome : "failure") or siem.sqli : true '
              'or siem.ruta_sensible : true or siem.herramienta_ataque : true or event.dataset : "siem.red"')


# ---- columnas de Lens --------------------------------------------------------
def c_count(label="Eventos", kql=None):
    c = {"label": label, "customLabel": True, "dataType": "number", "operationType": "count", "isBucketed": False,
         "scale": "ratio", "sourceField": "___records___", "params": {"emptyAsNull": True}}
    if kql:
        c["filter"] = {"query": kql, "language": "kuery"}
    return c


def c_unique(campo, label, kql=None):
    c = {"label": label, "customLabel": True, "dataType": "number", "operationType": "unique_count",
         "isBucketed": False, "scale": "ratio", "sourceField": campo, "params": {"emptyAsNull": True}}
    if kql:
        c["filter"] = {"query": kql, "language": "kuery"}
    return c


def c_fecha(intervalo="auto", label="Fecha"):
    return {"label": label, "customLabel": True, "dataType": "date", "operationType": "date_histogram",
            "sourceField": "@timestamp", "isBucketed": True, "scale": "interval",
            "params": {"interval": intervalo, "includeEmptyRows": True, "dropPartials": False}}


def c_terms(campo, label, orden, tamano=10, tipo="string"):
    return {"label": label, "customLabel": True, "dataType": tipo, "operationType": "terms", "sourceField": campo,
            "isBucketed": True, "scale": "ordinal",
            "params": {"size": tamano, "orderBy": {"type": "column", "columnId": orden}, "orderDirection": "desc",
                       "otherBucket": False, "missingBucket": False, "parentFormat": {"id": "terms"},
                       "include": [], "exclude": [], "includeIsRegex": False, "excludeIsRegex": False}}


def c_filtros(label, filtros):
    return {"label": label, "customLabel": True, "dataType": "string", "operationType": "filters",
            "isBucketed": True, "scale": "ordinal",
            "params": {"filters": [{"label": l, "input": {"query": q, "language": "kuery"}} for l, q in filtros]}}


# ---- objetos -----------------------------------------------------------------
def lens(oid, titulo, tipo_vis, data_view, columnas, visualizacion, kql=""):
    capa = "capa1"
    return {
        "id": oid, "type": "lens",
        "attributes": {
            "title": titulo, "description": "", "visualizationType": tipo_vis,
            "state": {
                "datasourceStates": {"formBased": {"layers": {capa: {
                    "columns": columnas, "columnOrder": list(columnas), "incompleteColumns": {}}}}},
                "visualization": visualizacion,
                "query": {"query": kql, "language": "kuery"}, "filters": [], "internalReferences": [],
                "adHocDataViews": {},
            },
        },
        "references": [{"type": "index-pattern", "id": data_view, "name": f"indexpattern-datasource-layer-{capa}"}],
    }


def metrica(oid, titulo, data_view, columna, kql="", color=None):
    vis = {"layerId": "capa1", "layerType": "data", "metricAccessor": "m"}
    if color:
        vis["color"] = color
    return lens(oid, titulo, "lnsMetric", data_view, {"m": columna}, vis, kql)


def barras(oid, titulo, data_view, x, y, division=None, kql="", serie="bar_stacked", horizontal=False):
    # Lens exige las columnas de agrupación (desglose y eje X) antes que las métricas.
    cols = {"d": division, "x": x, "y": y} if division else {"x": x, "y": y}
    capa = {"layerId": "capa1", "layerType": "data", "seriesType": "bar_horizontal" if horizontal else serie,
            "xAccessor": "x", "accessors": ["y"], "showGridlines": False}
    if division:
        capa["splitAccessor"] = "d"
    vis = {"legend": {"isVisible": bool(division), "position": "right"}, "valueLabels": "hide",
           "preferredSeriesType": capa["seriesType"], "layers": [capa],
           "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False}}
    return lens(oid, titulo, "lnsXY", data_view, cols, vis, kql)


def tabla(oid, titulo, data_view, columnas, kql=""):
    vis = {"layerId": "capa1", "layerType": "data", "columns": [{"columnId": c} for c in columnas]}
    return lens(oid, titulo, "lnsDatatable", data_view, columnas, vis, kql)


def dona(oid, titulo, data_view, grupo, valor, kql=""):
    vis = {"shape": "donut", "layers": [{"layerId": "capa1", "layerType": "data", "primaryGroups": ["g"],
                                          "metrics": ["v"], "numberDisplay": "percent", "categoryDisplay": "default",
                                          "legendDisplay": "default", "nestedLegend": False}]}
    return lens(oid, titulo, "lnsPie", data_view, {"g": grupo, "v": valor}, vis, kql)


def busqueda(oid, titulo, data_view, columnas, kql=""):
    fuente = {"query": {"query": kql, "language": "kuery"}, "filter": [],
              "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
    return {
        "id": oid, "type": "search",
        "attributes": {"title": titulo, "columns": columnas, "sort": [["@timestamp", "desc"]],
                       "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(fuente)}},
        "references": [{"type": "index-pattern", "id": data_view,
                        "name": "kibanaSavedObjectMeta.searchSourceJSON.index"}],
    }


def mapa(oid, titulo, kql):
    capas = [
        {"id": "base", "type": "EMS_VECTOR_TILE", "visible": True, "alpha": 1, "includeInFitToBounds": True,
         "sourceDescriptor": {"type": "EMS_TMS", "isAutoSelect": True, "lightModeDefault": "road_map_desaturated"},
         "style": {"type": "EMS_VECTOR_TILE", "color": ""}},
        {"id": "ips", "type": "GEOJSON_VECTOR", "visible": True, "alpha": 0.8, "includeInFitToBounds": True,
         "label": "IPs sospechosas", "query": {"query": kql, "language": "kuery"},
         "sourceDescriptor": {"type": "ES_GEO_GRID", "id": "fuente-ips", "geoField": "source.geo.location",
                              "requestType": "point", "resolution": "FINE", "metrics": [{"type": "count"}],
                              "applyGlobalQuery": True, "applyGlobalTime": True, "applyForceRefresh": True,
                              "indexPatternRefName": "layer_1_source_index_pattern"},
         "style": {"type": "VECTOR", "isTimeAware": True, "properties": {
             "icon": {"type": "STATIC", "options": {"value": "marker"}},
             "fillColor": {"type": "STATIC", "options": {"color": "#E7664C"}},
             "lineColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
             "lineWidth": {"type": "STATIC", "options": {"size": 1}},
             "iconSize": {"type": "DYNAMIC", "options": {"minSize": 7, "maxSize": 30,
                                                         "field": {"name": "doc_count", "origin": "source"},
                                                         "fieldMetaOptions": {"isEnabled": True, "sigma": 3}}},
             "iconOrientation": {"type": "STATIC", "options": {"orientation": 0}},
             "labelText": {"type": "STATIC", "options": {"value": ""}},
             "labelColor": {"type": "STATIC", "options": {"color": "#000000"}},
             "labelSize": {"type": "STATIC", "options": {"size": 14}},
             "labelBorderColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
             "symbolizeAs": {"options": {"value": "circle"}},
             "labelBorderSize": {"options": {"size": "SMALL"}},
             "labelZoomRange": {"options": {"useLayerZoomRange": True, "minZoom": 0, "maxZoom": 24}},
             "labelPosition": {"options": {"position": "CENTER"}}}}},
    ]
    estado = {"zoom": 0.9, "center": {"lon": 25, "lat": 20}, "timeFilters": {"from": "now-7d", "to": "now"},
              "refreshConfig": {"isPaused": True, "interval": 0}, "query": {"query": "", "language": "kuery"},
              "filters": [], "settings": {"autoFitToDataBounds": False}}
    return {
        "id": oid, "type": "map",
        "attributes": {"title": titulo, "description": "", "layerListJSON": json.dumps(capas),
                       "mapStateJSON": json.dumps(estado), "uiStateJSON": json.dumps({"isLayerTOCOpen": False})},
        "references": [{"name": "layer_1_source_index_pattern", "type": "index-pattern", "id": DV_LOGS}],
    }


def tablero(oid, titulo, descripcion, paneles, desde, refresco_ms):
    """paneles: [(objeto, x, y, w, h)] en una grilla de 48 columnas."""
    panels, refs = [], []
    for i, (obj, x, y, w, h) in enumerate(paneles, start=1):
        pid = str(i)
        cfg = {}
        if obj["type"] == "map":
            cfg = {"isLayerTOCOpen": False, "hiddenLayers": [], "mapCenter": {"lat": 20, "lon": 25, "zoom": 0.9}}
        panels.append({"type": obj["type"], "panelIndex": pid, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                       "embeddableConfig": cfg, "panelRefName": f"panel_{pid}"})
        refs.append({"name": f"{pid}:panel_{pid}", "type": obj["type"], "id": obj["id"]})
    return {
        "id": oid, "type": "dashboard",
        "attributes": {
            "title": titulo, "description": descripcion, "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True,
                                       "syncTooltips": True, "hidePanelTitles": False}),
            "timeRestore": True, "timeFrom": desde, "timeTo": "now",
            "refreshInterval": {"pause": False, "value": refresco_ms},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"},
                                                                       "filter": []})},
        },
        "references": refs,
    }


# ============================================================================
# Dashboard ejecutivo (R8.6): para gente no técnica
# ============================================================================
e1 = metrica("siem-e-alertas-hoy", "Alertas de hoy", DV_ALERTAS, c_count("Alertas de hoy", HOY), color="#E7664C")
e2 = metrica("siem-e-graves-hoy", "Alertas graves de hoy (alta o crítica)", DV_ALERTAS,
             c_count("Graves hoy", f'{HOY} and kibana.alert.severity : ("high" or "critical")'), color="#BD271E")
e3 = metrica("siem-e-ips", "IPs atacantes distintas (7 días)", DV_LOGS,
             c_unique("source.ip", "IPs atacantes", SOSPECHOSO))
e4 = metrica("siem-e-eventos", "Eventos analizados", DV_LOGS, c_count("Eventos analizados"))
e5 = barras("siem-e-top-amenazas", "Top amenazas de hoy", DV_ALERTAS,
            c_terms("kibana.alert.rule.name", "Regla", "y", 10), c_count("Alertas", HOY), horizontal=True)
e6 = mapa("siem-e-mapa", "Mapa de IPs sospechosas", SOSPECHOSO)
e7 = barras("siem-e-tendencia", "Ataques por día y tipo (tendencia semanal)", DV_LOGS,
            c_fecha("1d", "Día"), c_count("Eventos"),
            c_filtros("Tipo de ataque", [
                ("Fuerza bruta SSH", 'event.dataset : "siem.auth" and event.outcome : "failure"'),
                ("Inyección SQL", "siem.sqli : true"),
                ("Rutas sensibles", "siem.ruta_sensible : true"),
                ("Escaneo de puertos", 'event.dataset : "siem.red"'),
                ("Errores 404", "http.response.status_code : 404"),
            ]))
e8 = barras("siem-e-salud", "Salud del sistema: eventos por fuente", DV_LOGS,
            c_fecha("auto"), c_count("Eventos"), c_terms("data_stream.dataset", "Fuente", "y", 6), serie="area_stacked")
e9 = metrica("siem-e-rechazados", "Logs rechazados (malformados)", DV_ERRORES, c_count("Rechazados"), color="#D6BF57")

ejecutivo = tablero(
    "siem-dashboard-ejecutivo", "SIEM - Ejecutivo",
    "Visión para gerencia: cuántas amenazas hay hoy, de dónde vienen y cómo va la semana (R8.6).",
    [(e1, 0, 0, 12, 8), (e2, 12, 0, 12, 8), (e3, 24, 0, 12, 8), (e4, 36, 0, 12, 8),
     (e5, 0, 8, 20, 15), (e6, 20, 8, 28, 15),
     (e7, 0, 23, 30, 14), (e8, 30, 23, 18, 10), (e9, 30, 33, 18, 4)],
    "now-7d", 60000)

# ============================================================================
# Dashboard operacional (R8.7): para el analista que investiga
# ============================================================================
o1 = busqueda("siem-o-alertas-abiertas", "Alertas activas", DV_ALERTAS,
              ["kibana.alert.rule.name", "kibana.alert.severity", "source.ip", "user.name", "kibana.alert.reason"],
              'kibana.alert.workflow_status : "open"')
o2 = tabla("siem-o-top-ips", "Top IPs (clic para filtrar todo el tablero)", DV_LOGS, {
    "ip": c_terms("source.ip", "IP origen", "n", 10, "ip"),
    "n": c_count("Eventos"),
    "f": c_count("Fallos", 'event.outcome : "failure"'),
    "p": c_unique("destination.port", "Puertos tocados"),
    "pais": {**c_terms("source.geo.country_name", "País", "n", 1), "isBucketed": False, "operationType": "last_value",
             "params": {"sortField": "@timestamp", "showArrayValues": False}, "scale": "ordinal",
             "filter": {"query": "source.geo.country_name : *", "language": "kuery"}},
}, "source.ip : *")
o3 = tabla("siem-o-top-usuarios", "Top usuarios en SSH", DV_LOGS, {
    "u": c_terms("user.name", "Usuario", "n", 10),
    "n": c_count("Intentos"),
    "f": c_count("Fallidos", 'event.outcome : "failure"'),
    "ok": c_count("Exitosos", 'event.outcome : "success"'),
}, 'event.dataset : "siem.auth" and user.name : *')
o4 = barras("siem-o-por-minuto", "Eventos por minuto y fuente", DV_LOGS,
            c_fecha("auto"), c_count("Eventos"), c_terms("data_stream.dataset", "Fuente", "y", 6))
o5 = dona("siem-o-acciones", "Qué está pasando (event.action)", DV_LOGS,
          c_terms("event.action", "Acción", "v", 8), c_count("Eventos"))
o6 = busqueda("siem-o-logs-vivo", "Logs en tiempo real", DV_LOGS,
              ["data_stream.dataset", "source.ip", "user.name", "event.action", "event.outcome", "message"])

operacional = tablero(
    "siem-dashboard-operacional", "SIEM - Operacional",
    "Para investigar un incidente: alertas abiertas, quién ataca, a qué usuario y los logs crudos (R8.7). "
    "Clic en una IP de la tabla filtra todo el tablero; desde 'Logs en tiempo real' se abre Discover.",
    [(o1, 0, 0, 48, 10),
     (o2, 0, 10, 24, 13), (o3, 24, 10, 24, 13),
     (o4, 0, 23, 32, 11), (o5, 32, 23, 16, 11),
     (o6, 0, 34, 48, 16)],
    "now-1h", 10000)

objetos = [e1, e2, e3, e4, e5, e6, e7, e8, e9, ejecutivo, o1, o2, o3, o4, o5, o6, operacional]

# Versión de esquema de cada tipo en Kibana 8.19. Sin esto Kibana cree que los objetos son de una
# versión vieja, intenta migrarlos y el import falla con error 500.
VERSIONES = {"lens": "8.9.0", "map": "8.4.0", "search": "10.5.0", "dashboard": "10.3.0"}
for o in objetos:
    o["coreMigrationVersion"] = "8.8.0"
    o["typeMigrationVersion"] = VERSIONES[o["type"]]

if __name__ == "__main__":
    salida = Path(__file__).resolve().parent / "dashboards" / "siem-dashboards.ndjson"
    with open(salida, "w", encoding="utf-8", newline="\n") as f:
        for o in objetos:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"{len(objetos)} objetos -> {salida}")

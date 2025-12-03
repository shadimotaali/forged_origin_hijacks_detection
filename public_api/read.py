from psycopg2.extensions import connection
import datetime




def boolean_to_str_legitimacy(val :bool):
    if val == True:
        return "legitimate"
    
    elif val == False:
        return "suspicious"
    
    else:
        return "unknown"
    



def execute_read_query(conn :connection, query, params=None):
    try:
        cursor = conn.cursor()
        if params is not None:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        result = cursor.fetchall()

        return True, result
    
    except Exception as e:
        return False, str(e)



def _build_match_list_safe(column: str, values: list[int]):
    if len(values) == 1:
        return f"{column} = %s", [values[0]]
    else:
        return f"{column} = ANY(%s)", [values]



def _build_conditions(
    asn=None,
    attackers=None,
    victims=None,
    inference_result=None,
    min_confidence_level=None,
    nb_max_aspaths=None,
    nb_min_aspaths=None,
    start_ts=None,
    stop_ts=None,
    new_link_ids=None
):
    conditions = []
    params = []

    if asn:
        cond1, p1 = _build_match_list_safe("as1", asn)
        cond2, p2 = _build_match_list_safe("as2", asn)
        conditions.append(f"({cond1} OR {cond2})")
        params.extend(p1 + p2)

    if attackers:
        conditions.append("attacker = ANY(%s)")
        params.append(attackers)

    if victims:
        conditions.append("victims && %s::BIGINT[]")
        params.append(victims)

    if inference_result is not None:
        conditions.append("is_legit = %s")
        params.append(inference_result)

    if min_confidence_level:
        conditions.append("confidence_level >= %s")
        params.append(min_confidence_level)

    if nb_max_aspaths:
        conditions.append("nb_aspaths <= %s")
        params.append(nb_max_aspaths)

    if nb_min_aspaths:
        conditions.append("nb_aspaths >= %s")
        params.append(nb_min_aspaths)

    if start_ts:
        conditions.append("timestamp >= %s")
        params.append(start_ts)

    if stop_ts:
        conditions.append("timestamp <= %s")
        params.append(stop_ts)

    if new_link_ids:
        cond, p = _build_match_list_safe("id_", new_link_ids)
        conditions.append(cond)
        params.extend(p)

    return conditions, params



def get_new_links(pg_helper :connection,
                  asn :list[int],
                  attackers :list[int],
                  victims :list[int],
                  inference_result :bool,
                  min_confidence_level :int,
                  nb_max_aspaths :int,
                  nb_min_aspaths :int,
                  start_date :int,
                  stop_date :int,
                  new_link_ids :list[int]):


    base_query = """
        SELECT id_, timestamp, as1, as2, attacker, victims, is_legit,
               confidence_level, nb_aspaths, is_recurrent, user_comment,
               authorize_others
        FROM new_links
    """

    conditions, params = _build_conditions(
        asn=asn,
        attackers=attackers,
        victims=victims,
        inference_result=inference_result,
        min_confidence_level=min_confidence_level,
        nb_max_aspaths=nb_max_aspaths,
        nb_min_aspaths=nb_min_aspaths,
        start_ts=start_date,
        stop_ts=stop_date,
        new_link_ids=new_link_ids
    )
    
    ### --- Add all filters to the query --- ###
    if conditions:
        query = base_query + " WHERE " + " AND ".join(conditions)
    else:
        query = base_query

    query += ";"

    ok, res = execute_read_query(pg_helper, query, params=params)
    if not ok:
        print(res)
        return {"code": 404, "detail": "Unable to execute the query. Please retry later."}
    

    results :list[dict[str, int | str | list[int]]] = list()

    for id, observed_at, asn1, asn2, attacker, victims, classification, confidence_level, num_paths, is_reccurent, user_feedback, authorize_others in res:
        case_ = dict()
    
        case_["id"] = id
        case_["date"] = observed_at
        case_["as1"] = asn1
        case_["as2"] = asn2
        case_["presumed_attacker"] = attacker
        case_["presumed_victims"] = victims
        case_["inference_result"] = boolean_to_str_legitimacy(classification)
        case_["confidence_level"] = confidence_level
        case_["nb_aspaths_observed"] = num_paths
        case_["is_reccurent"] = is_reccurent

        if user_feedback and authorize_others:
            case_["operator_feedback"] = user_feedback

        results.append(case_)

    return {"code": 200, "results": results}




def get_inference_details(pg_helper :connection,
                          new_link_ids :list[int]):
    
    ### --- Build the query to get the inference details --- ###
    query = "SELECT timestamp, as1, as2, new_link_id, vp_asn, vp_ip, aspath, prefix, is_legit FROM inferences WHERE new_link_id = ANY(ARRAY{});".format(new_link_ids)

    ### --- Retreive results --- ###
    ok, res = execute_read_query(pg_helper, query)
    if not ok:
        return {"code": 404, "detail": "Unable to execute the query. Please retry later."}

    
    results :dict[int, list[tuple[str, int, int, int, str, str, str, str, int, list[str], list[str]]]] = dict()

    for observed_at, asn1, asn2, inference_id, peer_asn, peer_ip, as_path, prefix, is_legit in res:

        case_ = (observed_at, 
                 asn1, 
                 asn2, 
                 peer_asn, 
                 peer_ip, 
                 as_path, 
                 prefix, 
                 is_legit, 
                 0 if is_legit else 5, 
                 list(), 
                 list())

        if inference_id not in results:
            results[inference_id] = list()

        results[inference_id].append(case_)

    return {"code": 200, "results": results}


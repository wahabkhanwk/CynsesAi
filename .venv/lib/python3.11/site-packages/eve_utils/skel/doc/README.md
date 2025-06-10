# {$project_name}

The audience of this README is the **client developer**, i.e. someone who will **use** `{$project_name}`.

If you are an **API developer** who will make changes to `{$project_name}` itself, please see [`src/{$project_name}/README.md`](./src/{$project_name}/README.md).



## Getting Started

If you are running a local instance using all of the defaults, the API is served here http://localhost:2112. 

Wherever your instance of the API is, this doc will refer to its location as `{BASE_API_URL}`.



## Authorization

If your API is equipped with auth, there are two ways a client can authenticate.

1. OAuth2 (Bearer token)
2. If the instance of the API you are using was configured with ES_ADD_BASIC, there are four "backdoor" users you can use

See the [Authorization doc](./doc/Authorization.md) for more details.

**IMPORTANT**:  If you use a user with the multitenant permission (e.g. root:password) when you POST resources you must add a `_tenant` field with the region code of a valid region.  If you do not, only other multitenant users will see that resource.  <u>It will be invisible to single tenant users.</u>   If it happens (perhaps on purpose) you can always PATCH the `_tenant` field later.

By default the `_tenant` field does not appear when you GET resources.  You can view the field with the [projection query string](https://docs.python-eve.org/en/stable/features.html#projections).

e.g.

`GET {resource_href}?projection={"_tenant":1,"name":1}`

Note: when using query strings that have curly brackets against an instance of the API behind AWS API Gateway, the curly brackets must be urlencoded.



## General terms

- **resource** - similar to an entity, it's the thing you GET.  It's the R in URL.  The set of resources comprise the domain the API is responsible for managing.  There are two basic kinds of resources:
  - **collection** - a special resource, which is a set of individual resources, e.g. if you GET a members collection you get a list of members
  - **item** - a resource that stands by itself, i.e. is not a collection
- **hypermedia** - a representation of a resource that contains link relations as part of its definition.  
  - For example, HTML is a hypermedia type because an application can discover links by following <a> and <link> tags.  
  - JSON is not hypermedia - although it *can* contain links, there is no defined standard an application can know in advance.  
  - [HAL](https://en.wikipedia.org/wiki/Hypertext_Application_Language) is an extension of JSON which provides a standard definition for link discovery.

- **link relation** - or **rel** for short:  provides the semantic meaning of a link.  
  - There are [standardized](https://www.iana.org/assignments/link-relations/link-relations.xhtml) rels.  An API may define its rels either in compliance with a standard like IANA's or in its own scope.  
  - Once the rels are published, a new hypermedia type is effectively created (and can be registered with IANA, if general purpose enough).  
  - Client developers must be aware of the API's hypermedia type(s) and link relations, as that forms the "contract".  The contract does not include the value of `href` behind a rel - those may change without notice and without breaking the "contract"
  - The href associated with a link relation can be an absolute reference (staring with http) or relative (usually starting with /).  
  - If the href is relative, append it to `{BASE_API_URL}` to perform the operation - most http libraries can automate that for you.

- **affordance** - a link provided by hypermedia, identified by a rel, which allows the client to operate on the resource, either to navigate to related resources or to change the state of the application.



## Hypermedia API

Hypermedia is the organizing principle behind `{$project_name}`  Its main goal is to avoid client coupling - allowing the API and UI to evolve independently.  At least in theory, the only URL a client application needs to know is `{BASE_API_URL}`.  The rest is discoverable by following link relations.  If you follow this principle, your client will never break (after v0.8.0) no matter how the server side configuration changes.

This API uses a hypermedia type that is very similar to [HAL](https://en.wikipedia.org/wiki/Hypertext_Application_Language), i.e. it is JSON that reserves the object name `_links` to provide link relations.

Request: `GET {person_url}`

Response:

```json
{
    "firstName": "Clark",
    "lastName": "Kent",
    "_links": {
        "self": {
        	"href": "http://example.com/api/people/9843"
        },
        "address": {
        	"href": "http://example.com/api/addresses/3498"
        }
    }
}
```

### A couple of examples

To summarize with an pseudocode example, to get a resource:

```
response = GET {BASE_API_URL}
resource_url =  response.body._links.resource_rel.href
GET {resource_url}
```

When a parent resource is related to a child collection, you can POST a new child to a parent's collection like this:

```
response = GET {parent_url}
child_collection_url = response.body._links.child_rel.href
POST {child_collection_url}  -d child_data
```

### URL Templates

Typically a client application follows a link rel's `href` blindly (never parse an `href`!).  But when given a URL template, the client application can build its own URL.  In general a URL template is a partial `href` containing a placeholder which the client application replaces with some other field value.  See the `policy` rel in this example:

```json
{
   "name": "Bob",
   "policy_number": "A7394",
   "_links": {
   		"self": {
   			"href": "/members/1234"
   		},
   		"policy": {
   			"href": "/policies/{policy_number}"
   		}
   }
}
```

`{$project_name}` does not provide URL templates at this time.  In practice it is sometimes safe to use "assumed" templates to build URLs, as long as they are confirmed to remain valid with each API release.  Assumed URL templates are usually easy to fix when they break, as the new hrefs will be available in the API itself.


## Link Relations

Here are the link relations that form the "contract" provided by `{$project_name}`

### navigation affordances

* **self** - sometimes when an item appears in a collection, not all of its fields are populated.  GET this rel to fetch the complete record.  Also useful to GET self to check if there has been an update since last GET
* *parent - ignore this rel*
* **next** - when GETting a collection by page, this rel takes you to the next page
* **prev** - when GETting a collection by page, this rel takes you to the previous page
* **last** - when GETting a collection by page, this rel takes you to the last page
* **collection** - the collection this resource belongs to (applies to collections and items)

### api config affordances

* **logging** - GET to see log handlers and their verbosity levels.  Modify and PUT back to change verbosity levels
* **settings** - GET to see the value of environment variables and versions of the API and key components


### domain/collection affordances

Note: each of the following resource items have _tags (array of string) and _x (freeform JSON) fields.  Use _tags as you see fit.  If you need to save data to an item and there is no field, you can use _x.  Do this advisedly - it would be better to request the "missing" field be added to the schema.

TODO: document your domain model here


#### Parent/child

Each one-to-many relationship depicted above is managed via hypermedia - i.e. get from the parent to the child by way of the parent's `_links` and the rel of the child.  For example, to GET a list of brands for a region:

```
region = GET {region_url}
brand_url = region.body._links.brands.href
brands = GET {brand_url}
for each brand in brands.body._items...
```



## Using the API

`{$project_name}` is built with [Eve](https://docs.python-eve.org/en/stable/) and enhanced by [eve-utils](https://github.com/pointw-dev/eve-utils).  What follows is a list of some of the features provided by Eve.  You can learn more from its [feature documentation](https://docs.python-eve.org/en/stable/features.html).  There are more info and resources in this project [confluence page](https://cri.atlassian.net/wiki/spaces/I/pages/348291073/Introduction+to+Python+Eve+Cerberus+eve-utils).

### Pagination

* When doing a GET on a collection, the default max results is set to 1000 (change this default at deploy time by setting ES_PAGINATION_DEFAULT)

* You can override this value with a query string: e.g. `GET {features_url}?max_results=50`

* The max_results cannot exceed ES_PAGINATION_LIMIT which is currently set to 3000 (changeable at deploy time)

* The response body will contain a _meta object which lets you know if you have all of the items in the collection.  E.g. the above request had this _meta object:

  ```json
   "_meta": {
   	"page": 1,
      "max_results": 50,
      "total": 3291
  }   
  ```

* If the response body did not return all items in the collection:
  * _meta.max_results will be less than _meta.total
  * You can also use the **next**, **prev**, **last** affordances (see above)

* You can jump to any page with a query string, e.g. 

  ```
  GET {features_url}?page=2
  GET {features_url}?max_results=50&page=7 
  ```

* https://docs.python-eve.org/en/stable/features.html#pagination

### Filtering

* You can filter a collection with query strings, e.g. GET `{features_url}?where=category=="Exterior Features"`
* There are two types of where values
  * Python: create a conditional expression (e.g. `field==value`, `field!=value`, `field==value1 or field==value2`)
  * Mongo: use the mongo query definition language (e.g. `{ "_updated": {"$gte": "2021-10-01"}}` )
    * Note:  When the API is behind an AWS API Gateway (as it currently is when running "serverless"), the **curly brackets must be urlencoded**.
* https://docs.python-eve.org/en/stable/features.html#filtering

### Sorting

* Not much I can add that isn't in the doc...
* https://docs.python-eve.org/en/stable/features.html#sorting)

### Optimistic Concurrency

* To change a document after it has been POST’ed, you must supply an If-Match header with the correct ETag.  

  * If you do not, you will receive a 428 Precondition Failed.
  * This applies to PATCH, PUT, DELETE requests.  

* e.g. To Change the name of a feature:

  ```
  GET {feature_item_url}
  etag = response.body._etag
  data = {"name": "New Name"}
  PATCH {feature_item_url} -H "If-Match {etag}" -d data
  ```

* If you receive a 412 Precondition Failed, that means someone else made a change between the GET and the PATCH.  The client will have to handle this as appropriate (notify the user, offer to refresh/merge, etc.)
* https://docs.python-eve.org/en/stable/features.html#data-integrity-and-concurrency-control

### Embedded Resource Serialization

* When two resources are related (usually parent/child) that relationship is formed by one resource having a field that is the value of the `_id` of the other

* `{$project_name}` follows a field naming convention so you know when such a field is "embeddable"

  * When the field that holds the other's `_id` value is named like this: `_other_ref` (i.e. starts with underscore, ends with "_ref"), that is an embeddable resource 

* If you GET a resource with a value like this, you can add `embedded` to the query string, specifying which field to embed.  

* This will cause the API to fetch both the resource AND the other resource, embedding the other resource where that in place of the id value.

  for example:
  GET {brand_href}

  ```json
  {
      "name": "AlfaRomeo",
      "code": "Y",
      "_region_ref": "618e5bc4299111a411e71854",
      ...
      ...
  }
  ```

  GET {brand_href}?embedded={"_region_ref":1}

  ```json
  {
      "name": "AlfaRomeo",
      "code": "Y",
      "_region_ref": {
          "name": "United States of America",
          "code": "US",
          "languages": [
              {
                  "code": "en-us",
                  "name": "English (US)"
              }
          ],
          ...
          ...
      },
      ...
      ...
  }
  ```

  Note: when using query strings with curly brackets, they must be urlencoded before sending to an AWS API Gateway. 

* https://docs.python-eve.org/en/stable/features.html#embedded-resource-serialization

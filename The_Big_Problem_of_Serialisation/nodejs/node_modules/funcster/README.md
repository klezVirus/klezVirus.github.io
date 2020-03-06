# funcster

This library contains utilities for serializing and deserializing functions. It provides recursive traversal to discover both serialized and unserialized functions nested within objects and arrays. This is particularly useful for embedding functions into JSON objects.

## Security warning

This package performs the equivalent of `eval`, and thus should only be used to deserialize functions delivered from trusted sources. Do not use any of the deserialization functions on strings fron untrusted sources.

## Installation

    npm install funcster

## Function reference

### serialize(function, [marker])

```js
serialize(function() { return "Hello world!" });
// -> { __js_function: 'function() { return "Hello world!" }' }
```

----

### deepSerialize(root, [marker])

```js
lib = {
  moduleA: {
    functions: {
      helloWorld: function() { return "Hello world!" }
    }
  },
  moduleB: {
    functions: {
      goodbyeWorld: function() { return "Goodbye world!" }
    }
  },
};

funcster.deepSerialize(lib);

// -> {
//      moduleA: {
//        functions: {
//          helloWorld: { __js_function: 'function() { return "Hello world!" }' }
//        }
//      },
//      moduleB: {
//        functions: {
//          goodbyeWorld: { __js_function: 'function() { return "Goodbye world!" }' }
//        }
//      },
//    }
```

----

### deepDeserialize(root, [marker, [moduleOpts]])

#### Security warning

`deepDeserialize` performs code evaluation on strings, and is susceptible to arbitrary code injection. Please make sure that `root` comes from a trusted source before using it.

#### Example

```js
serializedLib = {
  moduleA: {
    functions: {
      helloWorld: { __js_function: 'function() { return "Hello world!" }' }
    }
  },
  moduleB: {
    functions: {
      goodbyeWorld: { __js_function: 'function() { return "Goodbye world!" }' }
    }
  },
};

deserializedLib = funcster.deepDeserialize(serializedLib);
deserializedLib.moduleA.functions.helloWorld(); // -> Hello world!
deserializedLib.moduleB.functions.goodbyeWorld(); // -> Hello world!
```

Available options:

#### globals (object)

This option injects objects from the host context into the function evaluation context. The key is the name of the object inside the function evaluation context, and the value is the object in the host context.

```js
deserializedLib = funcster.deepDeserialize(serializedLib, {
  globals: { foo: true }
});
```

#### requires (object)

This option injects `require`-able modules into the function evaluation context. These modules will be **re-required** in the host context, generating distinct module objects to those that might already exist. This is a safer method of granting serialized functions access to common libraries.

```js
deserializedLib = funcster.deepDeserialize(serializedLib, {
  requires: { _: 'underscore' }
});
```

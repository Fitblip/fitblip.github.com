---
layout: landing
---
{% for post in site.posts %}
<header>
	<div class="unit-head">
		<div class="unit-inner unit-head-inner">
			<a href="{{ root_url }}{{ post.url }}"><h1 class="h2 entry-title">{{ post.title }} ({{post.date | date: "%b %-d %Y"}})</h1></a>
		</div><!-- unit-inner -->
	</div><!-- unit-head -->
</header>

<div class="bd excerpts">
	<div class="misc-content">
		{{post.excerpt}}
		<div class="read-more">
			{% assign content_size = post.content | number_of_words %}
			{% assign excerpt_size = post.excerpt | number_of_words %}
			{% if excerpt_size == content_size %}
				<!-- DERP < DORP -->
				<!-- {{derp}} || {{dorp}} -->
				<a href="{{ root_url }}{{ post.url }}">Permalink/Comments</a>
			{% else %}
				<!-- DERP > DORP -->
				<!-- {{derp}} || {{dorp}} -->
				<a href="{{ root_url }}{{ post.url }}">[+] Continue reading</a>
			{% endif %}
		</div>
	</div><!-- misc-content -->
</div><!-- bd -->
{% endfor %}
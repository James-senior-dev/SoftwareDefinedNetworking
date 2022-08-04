# SoftwareDefinedNetworking
Der Datenaustausch innerhalb eines Netzwerkes ist um ein Vielfaches gestiegen, somit steigt die Auslastung, welches ein Netzwerksystem aushalten muss. Bei einem traditionellen Netzwerk würde das heißen, dass ein Netzwerkadministrator alle Netzwerkkomponenten wie Router, Switches und Firewalls etc. manuell konfigurieren müsste, um allen entsprechenden Anforderungen zu verwirklichen. Ferner müssen Netzwerkadministratoren viel Zeit in die Konfiguration investieren, um alles korrekt zu implementieren. Software Defined Networking bietet hierzu eine Alternativmöglichkeit zur Verwaltung einer Netzwerkumgebung. Im Gegensatz zu traditionellen Netzwerken trennt SDN die Kontrollschicht und die Datenschicht, und ermöglicht dadurch die Kontrolle des Netwerkes über das Netz. Im Mittelpunkt des Netzwerkes befindet sich ein SDN-Controller, der zur Konfiguration von allen Netzwerkkomponenten genutzt wird. Die SDN-Architektur ist auf drei Ebenen aufgeteilt und wird anhand von Abbildung nochmals visuell dargestellt. Die Anwendungsschicht enthält Applikationen für SDN wie Firewall und Loadbalancer und wird mithilfe der REST API bereitgestellt. Die  Kontrollschicht enthält den SND-Controller, worüber das gesamte Netzwerk gesteuert wird. Die Infrastrukturschicht enthält die Netzwerkkomponenten
wie Switches und Router und sind mit dem SDN-Controller verbunden, um die eingestellten Anforderungen vom Controller durchzusetzen. Die Architektur enthält mehrere Schnittstellen, sowohl eine Northbound API zwischen Anwendungsschicht und Kontrollschicht als auch eine Soutbound API zwischen Kontrollschicht und Infrastrukturschicht. Die Datenübertragung beim Southbound API erfolgt mit dem OpenFlow (OF) Protokoll. Bei der Weiterleitung eines Datenpakets wird die Weiterleitung auf der Datenschicht von einem Switch oder einem Router aufgenommen. Der SDN-Controller, der sich auf der Kontrollschicht befindet, entscheidet, wie das Datenpaket weitergeleitet wird. Dadurch können verschiedene Netzwerkfunktionen implementiert werden, die von den Switches und Routern umgesetzt werden müssen. Die Kommunikation zwischen dem SDN-Controller und den Switches in der Infrastrukturschicht wird durch Openflow realisiert. Durch die Änderung des flow tables im Switch, kann der Controller das Verhalten des Switches beeinflussen und so einstellen, dass die Instruktionen des Controllers umgesetzt werden. Im Gegensatz zu der traditionellen Weise die Netzwerkkomponenten manuell zu konfigurieren, kann durch die Trennung von Kontrollschicht und Datenschicht der Controller genutzt werden, um alle Konfigurationen von Komponenten im Netzwerk 
umzusetzen. Zudem kann durch das zentrale Management des Netzwerkes und das der SDN-Controller programmierbar ist, ein Administrator effizienter, flexibler und agiler Handeln. Besonders im Bereich Quality of Service muss ein Netzwerk agiler und flexibler als in der Vergangenheit sein. Somit kann Quality of Service mit SDN gewährleistet und einfacher umgesetzt werden. Logischerweise kann auch argumentiert werden, dass durch das zentrale Management über das Netz geringere Betriebskosten aufkommen, da die Konfigurationsänderungen effizienter umgesetzt werden können. Jedoch ist ein erwähnenswerter Nachteil, dass beim Ausfall eines SDN-Controllers in einem Netzwerk das gesamte Netzwerk ausfällt. Dies könnte durch eine Denial of Service attack ausgelöst werden. Somit könnte die Möglichkeit bestehen, mehrere Ausweichcontroller für solche Ereignisse vorzubereiten.

Im Folgenden werden die für die Implementierung verwendeten Hardware- und Softwareumgebungen kurz beschrieben. Dieses Projekt wurde auf VirtualBox Oracle VM Version 6.1 durchgeführt. Unter der Verwaltung von VirtualBox wurde Mininet-Emulator Version 2.3 und Floodlight Controller Version 1.2 installiert.Zur Ausführung von Programmen wurde außerdem Python3 installiert.

Mininet:
Mininet ist eine eine kostenlose Open-Source-Software, um ein Netzwerk zu emulieren. Es ermöglicht eine beliebige Topologie zu erstellen, wodurch ein Netzwerk von Hosts, Switches, virtuellen Links und ein Controller erstellt wird.

Floodlight:
Floodlight ist ein sogenannter SDN-Controller in der Control Plane. Dieser kommuniziert mit der Data Plane über ein Kommunikationsprotokoll namens OpenFlow und verwaltet diesen. Die REST-API wird über ein Python-Skript benutzt. Die Einbindung des Floodlight-Controllers in Eclipse ermöglicht die Implementierung, Untersuchung und das Debuggen verschiedenster Controller-Funktionen. Die gute Dokumentation des in Java geschriebenen Controllers und einige mit der Installation mitgelieferten Module geben dem Entwickler einen guten Start zur Entwicklung von Netzwerkfunktionen. Mit der Installation von Floodlight kommen sogenannte Module zum Einsatz. Die meisten der Module sind bereits aktiviert und bewältigen bestimmte Netzwerkaufgaben. Einer der Module ist der Learning Switch, welcher für die Speicherung der Routen zu den Hosts zuständig ist. Wenn ein Host einen anderen Host im gleichen Netzwerk erreichen will und der Switch die Route nicht kennt, wird das Paket als erstes an alle Netzwerkteilnehmern geschickt. Wenn der Zielhost antwortet, speichert der Switch die MAC-Adresse mit der jeweiligen Route in einer Tabelle ab. Wenn erneut ein Paket zum gleichen Empfänger will, wird über die Tabelle der Ausgangs-Port gelesen und das Paket darüber weitergeleitet. Weitere Beispielmodule wären der Load Balancer, der für einen Ausgleich des Datenverkehrs im gesamten Netzwerk sorgt. Über die REST-API stellt Floodlight die Netzwerktopologie über die Webbenutzeroberfläche grafisch dar.
